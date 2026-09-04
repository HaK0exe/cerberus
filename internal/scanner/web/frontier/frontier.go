// Package frontier implements the distributed crawl frontier: the
// scan_id/url/depth work-item message format, URL canonicalization,
// and a dedup layer keyed on SHA256(canonical URL) so that multiple
// crawl workers consuming the same queue never re-fetch the same
// page (S2-11).
//
// It is built on cerberus.JobQueue, the same abstraction used
// elsewhere in the project (in-memory today via internal/queue.MemQueue,
// SQS-backed once S2-10 lands) — this package does not know or care
// which backend it's talking to.
package frontier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// Message is a single frontier work item: "fetch this URL, at this
// depth, as part of this scan". It is the wire format published to
// and consumed from a JobQueue queue.
type Message struct {
	ScanID string `json:"scan_id"`
	URL    string `json:"url"`
	Depth  int    `json:"depth"`
}

// Marshal encodes m as JSON for JobQueue.Publish.
func (m Message) Marshal() ([]byte, error) { return json.Marshal(m) }

// Unmarshal decodes a JobQueue payload into a Message.
func Unmarshal(payload []byte) (Message, error) {
	var m Message
	err := json.Unmarshal(payload, &m)
	return m, err
}

// Canonicalize normalizes rawURL so that equivalent URLs compare
// equal: lower-cased scheme/host, default ports stripped (:80 for
// http, :443 for https), trailing slash on an empty path removed, and
// query parameters sorted by key. The fragment is dropped (it never
// affects what the server returns).
func Canonicalize(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("frontier: parsing URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("frontier: %q is not an absolute URL", rawURL)
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(stripDefaultPort(u.Scheme, u.Host))
	u.Fragment = ""

	if u.Path == "" {
		u.Path = "/"
	} else if u.Path != "/" {
		u.Path = strings.TrimSuffix(u.Path, "/")
		if u.Path == "" {
			u.Path = "/"
		}
	}

	if u.RawQuery != "" {
		q := u.Query()
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for i, k := range keys {
			vals := q[k]
			sort.Strings(vals)
			for j, v := range vals {
				if i > 0 || j > 0 {
					b.WriteByte('&')
				}
				b.WriteString(url.QueryEscape(k))
				b.WriteByte('=')
				b.WriteString(url.QueryEscape(v))
			}
		}
		u.RawQuery = b.String()
	}

	return u.String(), nil
}

func stripDefaultPort(scheme, host string) string {
	switch scheme {
	case "http":
		return strings.TrimSuffix(host, ":80")
	case "https":
		return strings.TrimSuffix(host, ":443")
	default:
		return host
	}
}

// FingerprintURL returns SHA256(canonical URL) as hex, the dedup key
// specified by S2-11.
func FingerprintURL(canonicalURL string) string {
	sum := sha256.Sum256([]byte(canonicalURL))
	return hex.EncodeToString(sum[:])
}

// Deduper answers "has this canonical URL already been claimed by
// some worker?" atomically, so two workers racing on the same URL
// never both get a "yes, go fetch it" answer.
type Deduper interface {
	// MarkIfNew reports true and records canonicalURL as seen if it
	// had not been seen before; reports false (without side effects)
	// if it was already seen.
	MarkIfNew(canonicalURL string) bool
}

// InMemoryDeduper is a process-local, concurrency-safe Deduper. It
// backs single-process crawls (internal/scanner/web.Crawler) and unit
// tests; a shared-storage implementation (e.g. Redis/DynamoDB-backed)
// is what would let independent worker *processes* share dedup state
// once S2-10 (SQS) lands — that backend is out of this issue's scope,
// the interface is what makes it a drop-in swap later.
type InMemoryDeduper struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func NewInMemoryDeduper() *InMemoryDeduper {
	return &InMemoryDeduper{seen: make(map[string]struct{})}
}

func (d *InMemoryDeduper) MarkIfNew(canonicalURL string) bool {
	key := FingerprintURL(canonicalURL)
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.seen[key]; ok {
		return false
	}
	d.seen[key] = struct{}{}
	return true
}

// Frontier publishes and consumes Messages on a JobQueue queue,
// deduplicating on the canonical URL before publishing so that
// multiple producers enqueueing the same discovered link only result
// in one fetch.
type Frontier struct {
	Queue cerberus.JobQueue
	Dedup Deduper
	Name  string // queue name, typically "web-frontier:<scan_id>"
}

// New returns a Frontier over queue, deduplicating with dedup (a
// fresh NewInMemoryDeduper() if dedup is nil).
func New(queue cerberus.JobQueue, name string, dedup Deduper) *Frontier {
	if dedup == nil {
		dedup = NewInMemoryDeduper()
	}
	return &Frontier{Queue: queue, Dedup: dedup, Name: name}
}

// Push canonicalizes rawURL and publishes a Message for it, unless
// that canonical URL has already been pushed (by this or any other
// producer sharing the same Dedup). Returns whether it was newly
// pushed.
func (f *Frontier) Push(ctx context.Context, scanID, rawURL string, depth int) (bool, error) {
	canon, err := Canonicalize(rawURL)
	if err != nil {
		return false, err
	}
	if !f.Dedup.MarkIfNew(canon) {
		return false, nil
	}
	payload, err := Message{ScanID: scanID, URL: canon, Depth: depth}.Marshal()
	if err != nil {
		return false, err
	}
	if err := f.Queue.Publish(ctx, f.Name, payload); err != nil {
		return false, err
	}
	return true, nil
}

// Consume returns a channel of decoded Messages, mirroring
// JobQueue.Consume but with JSON decoding applied. A malformed
// payload is dropped rather than sent (the queue is trusted
// internal infrastructure, not attacker-controlled input, but a
// worker should never crash on a bad message).
func (f *Frontier) Consume(ctx context.Context) (<-chan Message, error) {
	raw, err := f.Queue.Consume(ctx, f.Name)
	if err != nil {
		return nil, err
	}
	out := make(chan Message)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case payload, ok := <-raw:
				if !ok {
					return
				}
				msg, err := Unmarshal(payload)
				if err != nil {
					continue
				}
				select {
				case out <- msg:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}
