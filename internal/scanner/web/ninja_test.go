package web

import (
	"net/http"
	"net/url"
	"testing"
)

func mustParseNinjaURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	return u
}

func TestNinjaUserAgent_ReturnsPoolEntry(t *testing.T) {
	pool := make(map[string]bool, len(ninjaUserAgents))
	for _, ua := range ninjaUserAgents {
		if ua == "" {
			t.Fatal("ninja pool must not contain an empty User-Agent")
		}
		pool[ua] = true
	}
	if len(ninjaUserAgents) < 3 {
		t.Fatalf("expected at least 3 ninja User-Agents, got %d", len(ninjaUserAgents))
	}

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		ua := NinjaUserAgent()
		if !pool[ua] {
			t.Fatalf("NinjaUserAgent returned %q, not a pool entry", ua)
		}
		seen[ua] = true
	}
	if len(seen) < 2 {
		t.Fatal("expected random picks across 50 draws to cover at least 2 pool entries")
	}
}

func TestNinjaHeaders_SetsBrowserHeaders(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/page", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	NinjaHeaders(req)

	if got := req.Header.Get("Accept"); got != "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" {
		t.Errorf("Accept = %q, want browser-like value", got)
	}
	if got := req.Header.Get("Accept-Language"); got != "en-US,en;q=0.9" {
		t.Errorf("Accept-Language = %q, want %q", got, "en-US,en;q=0.9")
	}
	if got := req.Header.Get("Upgrade-Insecure-Requests"); got != "1" {
		t.Errorf("Upgrade-Insecure-Requests = %q, want %q", got, "1")
	}
	// No Referer was set: none must be fabricated.
	if got := req.Header.Get("Referer"); got != "" {
		t.Errorf("Referer = %q, want empty (never fabricated)", got)
	}
}

func TestNinjaHeaders_DoesNotClobberUserAgent(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("User-Agent", NinjaUserAgent())
	before := req.Header.Get("User-Agent")

	NinjaHeaders(req)

	if got := req.Header.Get("User-Agent"); got != before {
		t.Errorf("NinjaHeaders changed User-Agent from %q to %q", before, got)
	}
}

func TestNinjaHeaders_Referer(t *testing.T) {
	cases := []struct {
		name    string
		target  string
		referer string
		want    string // expected Referer after NinjaHeaders
	}{
		{"no referer stays absent", "https://example.com/a", "", ""},
		{"same-host referer kept", "https://example.com/a", "https://example.com/", "https://example.com/"},
		{"same-host nested referer kept", "https://example.com/a/b", "https://example.com/other?q=1", "https://example.com/other?q=1"},
		{"cross-site referer stripped", "https://example.com/a", "https://evil.test/start", ""},
		{"unparsable referer stripped", "https://example.com/a", "://bad", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.target, nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			NinjaHeaders(req)
			if got := req.Header.Get("Referer"); got != tc.want {
				t.Errorf("Referer = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNinjaHeaders_NilSafe(t *testing.T) {
	// Must not panic on nil request or nil header map / URL.
	NinjaHeaders(nil)
	NinjaHeaders(&http.Request{Method: http.MethodGet, URL: mustParseNinjaURL(t, "https://example.com/")})
}

func TestNinjaDefaults_Ranges(t *testing.T) {
	opts := NinjaDefaults()

	if opts.RateLimit < 0.3 || opts.RateLimit > 0.5 {
		t.Errorf("RateLimit = %v, want within [0.3, 0.5]", opts.RateLimit)
	}
	if opts.Jitter < 1.5 || opts.Jitter > 2.5 {
		t.Errorf("Jitter = %v, want within [1.5, 2.5]", opts.Jitter)
	}
	if opts.Concurrency != 1 {
		t.Errorf("Concurrency = %d, want 1", opts.Concurrency)
	}
	if opts.RespectRobots {
		t.Error("RespectRobots = true, want false in ninja mode")
	}
	if opts.ScanJavaScript {
		t.Error("ScanJavaScript = true, want false in ninja mode")
	}
	if opts.UserAgent == "" {
		t.Fatal("UserAgent must be pinned to a pool entry, got empty")
	}
	if !opts.LowProfile {
		t.Error("LowProfile = false, want true in ninja mode")
	}
	pool := make(map[string]bool, len(ninjaUserAgents))
	for _, ua := range ninjaUserAgents {
		pool[ua] = true
	}
	if !pool[opts.UserAgent] {
		t.Errorf("UserAgent = %q, not a pool entry", opts.UserAgent)
	}
}
