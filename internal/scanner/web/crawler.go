// SECURITY: every outbound request in this package goes through the
// single *http.Client built by ssrf.Guard.NewClient (see Crawler.Scan's
// use of c.SetClient) — DNS resolution, IP validation, and
// re-validation on every redirect hop happen inside that client's
// Transport/CheckRedirect. Do not add another HTTP client here, and
// do not call anything in net/http directly for a network fetch — see
// docs/security/ssrf.md.
package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gocolly/colly/v2"

	"github.com/HaK0exe/cerberus/internal/scanner"
	"github.com/HaK0exe/cerberus/internal/scanner/web/frontier"
	"github.com/HaK0exe/cerberus/internal/scanner/web/ssrf"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

const (
	// maxBodyBytes bounds any single response (HTML page, linked
	// script, or source map) colly will read into memory — the
	// decompression-bomb / oversized-body guard required by S2-09 and
	// exercised by the security suite in S2-12.
	maxBodyBytes = 25 * 1024 * 1024

	defaultDepth       = 2
	defaultMaxPages    = 100
	defaultConcurrency = 4
	defaultRateLimit   = 2.0
)

// Crawler is the default web scanner.Scanner implementation.
type Crawler struct {
	// Guard is the SSRF guard used to build the crawler's HTTP
	// client. Defaults to ssrf.NewGuard() when nil.
	Guard *ssrf.Guard
	// Warnf receives non-fatal warnings (robots.txt fetch failures,
	// etc). Defaults to writing to os.Stderr.
	Warnf func(format string, args ...any)
}

// New returns the default Crawler.
func New() *Crawler {
	return &Crawler{Guard: ssrf.NewGuard()}
}

var _ scanner.Scanner = (*Crawler)(nil)

func (cr *Crawler) warnf(format string, args ...any) {
	if cr.Warnf != nil {
		cr.Warnf(format, args...)
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// Scan crawls target (an http(s) URL) and emits one cerberus.Artifact
// per page (SourceWebPage) and, when opts.ScanJavaScript is set, one
// per inline or linked script (SourceWebScript).
func (cr *Crawler) Scan(ctx context.Context, target string, opts cerberus.ScanOptions) (<-chan cerberus.Artifact, error) {
	start, err := url.Parse(strings.TrimSpace(target))
	if err != nil {
		return nil, fmt.Errorf("web scanner: invalid URL %q: %w", target, err)
	}
	if start.Scheme != "http" && start.Scheme != "https" {
		return nil, fmt.Errorf("web scanner: unsupported scheme %q (want http or https)", start.Scheme)
	}

	depth := opts.Depth
	if depth <= 0 {
		depth = defaultDepth
	}
	maxPages := opts.MaxPages
	if maxPages <= 0 {
		maxPages = defaultMaxPages
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	rateLimit := opts.RateLimit
	if rateLimit <= 0 {
		rateLimit = defaultRateLimit
	}

	scope := Scope{AllowedDomains: opts.AllowedDomains, ExcludePaths: opts.ExcludePaths}

	guard := cr.Guard
	if guard == nil {
		guard = ssrf.NewGuard()
	}
	client := guard.NewClient(func(req *http.Request) error {
		// Enforced on every redirect hop, not just the starting URL —
		// see S2-08. IP/DNS re-validation for the same hop already
		// happens unconditionally inside the guard's Transport.
		if !scope.Allowed(req.URL) {
			return fmt.Errorf("scope: redirect to out-of-scope URL %s rejected", redactedURL(req.URL))
		}
		return nil
	})

	var robots *robotsCache
	if opts.RespectRobots {
		robots = newRobotsCache(client, cr.warnf)
	}

	c := colly.NewCollector(
		colly.MaxDepth(depth),
		colly.Async(true),
	)
	c.IgnoreRobotsTxt = true // we enforce robots.txt ourselves (S2-07), with fail-open semantics colly doesn't offer
	c.MaxBodySize = maxBodyBytes
	c.SetClient(client)
	if err := c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: concurrency,
		Delay:       time.Duration(float64(time.Second) / rateLimit),
	}); err != nil {
		return nil, fmt.Errorf("web scanner: configuring rate limit: %w", err)
	}

	dedup := frontier.NewInMemoryDeduper()
	out := make(chan cerberus.Artifact, 32)

	var fetched int64
	scanID := fmt.Sprintf("web-%d", time.Now().UnixNano())

	// claim reserves target for fetching (scope + canonical dedup +
	// page budget), returning false if it must not be fetched — the
	// single choke point every discovered URL passes through, whether
	// it goes on to be fetched by colly (pages) or fetchScript
	// (JS/source maps).
	claim := func(target *url.URL) bool {
		if target == nil || !scope.Allowed(target) {
			return false
		}
		canon, err := frontier.Canonicalize(target.String())
		if err != nil {
			return false
		}
		if !dedup.MarkIfNew(canon) {
			return false
		}
		if atomic.AddInt64(&fetched, 1) > int64(maxPages) {
			return false
		}
		return true
	}

	// fetchScript downloads target directly through the SSRF-guarded
	// client (bypassing colly's page-crawl depth entirely — a page's
	// own scripts are not "links one hop deeper", they're resources
	// of the page already claimed) applying a hard size cap
	// (decompression-bomb / oversized-body protection, S2-09/S2-12),
	// and recurses once into any source map it references.
	var fetchScript func(target *url.URL)
	fetchScript = func(target *url.URL) {
		if !claim(target) {
			return
		}
		if robots != nil && !robots.allowed(target) {
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			cr.warnf("web scanner: fetching %s: %v", redactedURL(target), err)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxScriptBytes+1))
		if err != nil {
			cr.warnf("web scanner: reading %s: %v", redactedURL(target), err)
			return
		}
		if int64(len(body)) > maxScriptBytes {
			cr.warnf("web scanner: %s exceeds max script size (%d bytes), skipping", redactedURL(target), maxScriptBytes)
			return
		}

		ct := resp.Header.Get("Content-Type")
		emit(ctx, out, cerberus.Artifact{
			ID:         canonicalOrRaw(target),
			SourceType: cerberus.SourceWebScript,
			URI:        target.String(),
			MIMEType:   ct,
			Content:    body,
			FetchedAt:  time.Now().UTC(),
		})

		if mapURL := scriptSourceMapURL(target, string(body)); mapURL != nil {
			fetchScript(mapURL)
		}
	}

	c.OnRequest(func(r *colly.Request) {
		if atomic.LoadInt64(&fetched) >= int64(maxPages) {
			r.Abort()
			return
		}
		if robots != nil && !robots.allowed(r.URL) {
			r.Abort()
			return
		}
	})

	c.OnResponse(func(resp *colly.Response) {
		ct := resp.Headers.Get("Content-Type")
		if !strings.Contains(ct, "text/html") && ct != "" {
			return
		}
		u := resp.Request.URL
		emit(ctx, out, cerberus.Artifact{
			ID:         canonicalOrRaw(u),
			SourceType: cerberus.SourceWebPage,
			URI:        u.String(),
			MIMEType:   ct,
			Content:    resp.Body,
			FetchedAt:  time.Now().UTC(),
		})

		if !opts.ScanJavaScript {
			return
		}
		scripts, err := extractScripts(u, string(resp.Body))
		if err != nil {
			return
		}
		for _, s := range scripts {
			if s.Inline {
				emit(ctx, out, cerberus.Artifact{
					ID:         canonicalOrRaw(u) + "#inline-script",
					SourceType: cerberus.SourceWebScript,
					URI:        u.String(),
					MIMEType:   "application/javascript",
					Content:    []byte(s.Body),
					FetchedAt:  time.Now().UTC(),
				})
				continue
			}
			fetchScript(s.URL)
		}
	})

	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		next := e.Request.AbsoluteURL(e.Attr("href"))
		if next == "" {
			return
		}
		nu, err := url.Parse(next)
		if err != nil {
			return
		}
		if jsExtension(nu.Path) {
			// Handled by the JS extraction pipeline (or skipped
			// entirely when ScanJavaScript is disabled), not as a
			// page to recurse into.
			return
		}
		if !claim(nu) {
			return
		}
		_ = e.Request.Visit(nu.String())
	})

	c.OnError(func(resp *colly.Response, err error) {
		if resp != nil && resp.Request != nil {
			cr.warnf("web scanner: fetching %s: %v", redactedURL(resp.Request.URL), err)
		}
	})

	go func() {
		defer close(out)
		if !claim(start) {
			cr.warnf("web scanner: start URL %s rejected by scope/SSRF policy", redactedURL(start))
			return
		}
		if err := c.Visit(start.String()); err != nil {
			cr.warnf("web scanner: %v", err)
		}
		c.Wait()
	}()

	_ = scanID // reserved for the distributed frontier (S2-11); see internal/scanner/web/frontier

	return out, nil
}

func emit(ctx context.Context, out chan<- cerberus.Artifact, a cerberus.Artifact) {
	select {
	case out <- a:
	case <-ctx.Done():
	}
}

func canonicalOrRaw(u *url.URL) string {
	if u == nil {
		return ""
	}
	if c, err := frontier.Canonicalize(u.String()); err == nil {
		return c
	}
	return u.String()
}

// redactedURL renders a URL without userinfo, for safe inclusion in
// warning/error messages.
func redactedURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	cp := *u
	cp.User = nil
	return cp.String()
}
