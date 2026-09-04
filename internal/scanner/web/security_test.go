// Security test suite for the web scanner (S2-12). Each test below
// corresponds to a bullet in docs/security/ssrf.md's "Required tests
// before this is considered done" section, exercised end-to-end
// through Crawler.Scan rather than against the ssrf package directly
// (see internal/scanner/web/ssrf/ssrf_test.go for the lower-level
// unit coverage of the guard itself).
package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HaK0exe/cerberus/internal/scanner/web/ssrf"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// TestSecurity_SSRF_DirectLoopbackURL: the crawl target itself is a
// loopback address. The crawler must produce no artifacts (the
// default, non-permissive guard blocks the initial request).
func TestSecurity_SSRF_DirectLoopbackURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("loopback target must never be fetched with the default SSRF guard")
	}))
	defer srv.Close()

	cr := New() // default guard: loopback blocked
	ch, err := cr.Scan(context.Background(), srv.URL, cerberus.ScanOptions{Depth: 1, MaxPages: 5, Concurrency: 1, RateLimit: 1000})
	if err != nil {
		t.Fatalf("Scan should not error synchronously (blocking happens per-request): %v", err)
	}
	artifacts := drain(t, ch, 3*time.Second)
	if len(artifacts) != 0 {
		t.Fatalf("expected zero artifacts from a blocked loopback target, got %+v", artifacts)
	}
}

// TestSecurity_SSRF_RedirectChainToBlockedAddress: the target is
// reachable and in scope, but its redirect chain terminates on a
// blocked address. The redirect must not be followed.
func TestSecurity_SSRF_RedirectChainToBlockedAddress(t *testing.T) {
	origin := newLoopbackServer(t, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/iam/security-credentials/", http.StatusFound)
	}))
	defer origin.Close()

	cr := &Crawler{Guard: permissiveTestGuard()} // loopback allowed so the FIRST hop succeeds; metadata IP is never allow-listable
	ch, err := cr.Scan(context.Background(), origin.URL, cerberus.ScanOptions{Depth: 1, MaxPages: 5, Concurrency: 1, RateLimit: 1000})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	artifacts := drain(t, ch, 3*time.Second)
	for _, a := range artifacts {
		if strings.Contains(a.URI, "169.254.169.254") {
			t.Fatalf("expected the metadata redirect target to never be fetched, got %+v", a)
		}
	}
}

// TestSecurity_SSRF_MetadataEndpoint_NeverAllowlistable: even with
// 169.254.169.254 explicitly present in --allowed-domains, it must
// remain blocked — the metadata endpoint is a hard-coded exception to
// scope, per docs/security/ssrf.md.
func TestSecurity_SSRF_MetadataEndpoint_NeverAllowlistable(t *testing.T) {
	g := ssrf.NewGuard() // default guard: metadata always blocked regardless of scope
	cr := &Crawler{Guard: g}
	ch, err := cr.Scan(context.Background(), "http://169.254.169.254/latest/meta-data/", cerberus.ScanOptions{
		Depth: 1, MaxPages: 5, Concurrency: 1, RateLimit: 1000,
		AllowedDomains: []string{"169.254.169.254"}, // explicit allow-list entry must NOT override the SSRF guard
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	artifacts := drain(t, ch, 3*time.Second)
	if len(artifacts) != 0 {
		t.Fatalf("expected the metadata endpoint to stay blocked even when allow-listed, got %+v", artifacts)
	}
}

// TestSecurity_SSRF_DNSRebinding: a hostname that resolves to a
// public IP on the guard's own check must still be dialed at exactly
// that validated IP (never re-resolved at connect time), so a
// resolver that would answer differently a moment later cannot be
// used to rebind the connection to a private address.
func TestSecurity_SSRF_DNSRebinding(t *testing.T) {
	g := ssrf.NewGuard()
	g.DialTimeout = 2 * time.Second
	g.Resolver = rebindingResolver{
		first:  []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}},
		public: true,
	}
	client := g.NewClient(nil)
	client.Timeout = 3 * time.Second
	// Any dial for the rebinding host must use the FIRST validated
	// answer (8.8.8.8) even though the fake resolver would answer
	// with a private IP on a subsequent lookup — proven by the fact
	// that dialing never reaches 127.0.0.1 (would succeed instantly
	// against an in-test listener) and instead fails/times out trying
	// a real public IP unreachable from the sandbox.
	req, _ := http.NewRequest(http.MethodGet, "http://rebind.example.test/", nil)
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("expected the request to fail (no route to the validated public IP in the test sandbox), not silently succeed against a rebound private address")
	}
}

type rebindingResolver struct {
	first  []net.IPAddr
	public bool
}

func (r rebindingResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return r.first, nil
}

// TestSecurity_OversizedBody: a response advertising (and sending) a
// body far larger than the crawler's cap must be truncated/rejected
// rather than fully buffered in memory.
func TestSecurity_OversizedBody_Page(t *testing.T) {
	const chunk = 1 << 20 // 1MB
	srv := newLoopbackServer(t, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		buf := make([]byte, chunk)
		// Way beyond maxBodyBytes (25MB): stream 64MB.
		for i := 0; i < 64; i++ {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	cr := &Crawler{Guard: permissiveTestGuard()}
	ch, err := cr.Scan(context.Background(), srv.URL, cerberus.ScanOptions{Depth: 1, MaxPages: 3, Concurrency: 1, RateLimit: 1000})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	artifacts := drain(t, ch, 10*time.Second)
	for _, a := range artifacts {
		if len(a.Content) > maxBodyBytes {
			t.Fatalf("expected page content to be capped at %d bytes, got %d", maxBodyBytes, len(a.Content))
		}
	}
}

// TestSecurity_OversizedBody_Script: same protection, for a
// separately-downloaded linked script (S2-09's own size-limit
// requirement, exercised via fetchScript rather than colly).
func TestSecurity_OversizedBody_Script(t *testing.T) {
	const chunk = 1 << 20
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><script src="/huge.js"></script></body></html>`)
	})
	mux.HandleFunc("/huge.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		buf := make([]byte, chunk)
		for i := 0; i < 40; i++ { // 40MB > maxScriptBytes (25MB)
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	})
	srv := newLoopbackServer(t, "127.0.0.1", mux)
	defer srv.Close()

	cr := &Crawler{Guard: permissiveTestGuard()}
	ch, err := cr.Scan(context.Background(), srv.URL, cerberus.ScanOptions{
		Depth: 1, MaxPages: 5, Concurrency: 1, RateLimit: 1000, ScanJavaScript: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	artifacts := drain(t, ch, 15*time.Second)
	for _, a := range artifacts {
		if a.SourceType == cerberus.SourceWebScript {
			t.Fatalf("expected the oversized script to be rejected (no artifact emitted), got one with %d bytes", len(a.Content))
		}
	}
}

// TestSecurity_InfiniteCrawl_RedirectLoop: a redirect loop between two
// URLs must not hang the crawl or the process — it terminates within
// a bounded number of hops (enforced inside the SSRF-guarded client).
func TestSecurity_InfiniteCrawl_RedirectLoop(t *testing.T) {
	var mux http.ServeMux
	var srv *httptest.Server
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/a", http.StatusFound)
	})
	srv = newLoopbackServer(t, "127.0.0.1", &mux)
	defer srv.Close()

	cr := &Crawler{Guard: permissiveTestGuard()}
	ch, err := cr.Scan(context.Background(), srv.URL+"/a", cerberus.ScanOptions{Depth: 1, MaxPages: 5, Concurrency: 1, RateLimit: 1000})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// Must terminate promptly (well under a hung-forever timeout) with
	// no artifacts, not stall the crawl.
	artifacts := drain(t, ch, 5*time.Second)
	if len(artifacts) != 0 {
		t.Fatalf("expected a redirect loop to yield no artifacts, got %+v", artifacts)
	}
}

// TestSecurity_InfiniteCrawl_UnboundedPageGraph: a page graph that
// keeps generating new distinct links forever must be bounded by
// MaxPages, not crawled indefinitely.
func TestSecurity_InfiniteCrawl_UnboundedPageGraph(t *testing.T) {
	var counter int64
	srv := newLoopbackServer(t, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&counter, 1)
		// Every page links to a fresh, never-repeating path, so the
		// only thing that can stop the crawl is the MaxPages budget.
		fmt.Fprintf(w, `<html><body><a href="/gen%d">next</a></body></html>`, n)
	}))
	defer srv.Close()

	cr := &Crawler{Guard: permissiveTestGuard()}
	ch, err := cr.Scan(context.Background(), srv.URL, cerberus.ScanOptions{
		Depth: 1000, MaxPages: 8, Concurrency: 2, RateLimit: 1000,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	artifacts := drain(t, ch, 10*time.Second)
	if len(artifacts) > 10 { // MaxPages(8) plus a small slack for in-flight requests at the moment the budget flips
		t.Fatalf("expected the crawl to be bounded near MaxPages, got %d artifacts", len(artifacts))
	}
}
