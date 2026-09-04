// Ninja-mode helpers for the web scanner: a browser-like identity and
// a low-and-slow request profile for authorized engagements where
// blending in matters more than crawl speed or coverage.
//
// These helpers are intentionally NOT wired to any CLI flag here (the
// --ninja flag is owned by a separate change). They only shape
// politeness/stealth signals — User-Agent, request headers, pacing —
// and never weaken safety enforcement: the SSRF guard (DNS+IP
// validation before the request and re-validation on every redirect
// hop, RFC1918/loopback/link-local plus 169.254.169.254 blocked) and
// crawl Scope still apply unchanged, and ProxyURL stays an explicit
// operator choice (ssrf.Guard.ProxyURL / --proxy), orthogonal to this
// profile.
package web

import (
	"crypto/rand"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// ninjaUserAgents is the pool NinjaUserAgent draws from. Versions are
// pinned to the desktop stable releases current at the time of writing
// (September 2026: Chrome 152, Firefox 155) — refresh them when they
// go stale, as an outdated version token is itself a bot signal. Only
// desktop Windows/macOS strings are listed: they are the most common
// traffic to blend into, and desktop Chrome's UA is frozen by the
// UA-reduction (minor version hard-coded to .0.0), so there is no
// point enumerating build variants.
var ninjaUserAgents = []string{
	// Chrome 152 on Windows 10/11 (Win 11 reports as 10.0).
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
	// Chrome 152 on macOS.
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
	// Firefox 155 on Windows 10/11.
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0",
	// Firefox 155 on macOS (version token frozen at 10.15 by Mozilla).
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:155.0) Gecko/20100101 Firefox/155.0",
}

// NinjaUserAgent returns one browser User-Agent picked uniformly at
// random from the ninja pool. It uses crypto/rand (not math/rand) so
// concurrent crawls cannot correlate picks via a shared PRNG sequence.
//
// Call it once per run (as NinjaDefaults does) and reuse the result
// for the whole crawl: a consistent fingerprint from one source IP
// looks like one user, while rotating the UA per request looks like
// automation trying to hide.
func NinjaUserAgent() string {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(ninjaUserAgents))))
	if err != nil {
		// crypto/rand failing is effectively impossible; fall back
		// to a fixed pool entry rather than an empty UA (which
		// would be far more conspicuous).
		return ninjaUserAgents[0]
	}
	return ninjaUserAgents[n.Int64()]
}

// NinjaHeaders stamps browser-like headers onto req in place:
//
//   - Accept: the value both Chrome and Firefox send (their common
//     subset), so it stays consistent no matter which pool UA the run
//     picked.
//   - Accept-Language: en-US, the single most common value.
//   - Upgrade-Insecure-Requests: 1, sent by both browsers on
//     navigations.
//
// It deliberately does NOT set Accept-Encoding: Go's Transport
// negotiates gzip transparently, and setting the header by hand would
// disable that. It does NOT set User-Agent either — that is owned by
// NinjaUserAgent/NinjaDefaults so a run keeps one stable identity.
//
// Referer is only ever preserved intra-site: a pre-set Referer whose
// host matches req.URL's host is kept (the future --ninja wiring can
// set it to the parent page to mimic in-site navigation); a missing,
// unparsable, or cross-site Referer is left absent/removed. Fabricating
// a cross-site Referer would leak the engagement's entry point, and
// sending none is the safe default.
func NinjaHeaders(req *http.Request) {
	if req == nil {
		return
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	ref := req.Header.Get("Referer")
	if ref == "" {
		return
	}
	if keepNinjaReferer(req.URL, ref) {
		return
	}
	req.Header.Del("Referer")
}

// keepNinjaReferer reports whether ref may be sent with a request to
// target: only when both parse and share the same hostname.
func keepNinjaReferer(target *url.URL, ref string) bool {
	if target == nil {
		return false
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return false
	}
	if refURL.Hostname() == "" || target.Hostname() == "" {
		return false
	}
	return strings.EqualFold(refURL.Hostname(), target.Hostname())
}

// NinjaDefaults returns the ScanOptions for a low-profile crawl.
//
// Tradeoff OPSEC vs couverture, assumé explicitement :
//
//   - OPSEC: Concurrency 1 with RateLimit 0.4 (~2.5 s base spacing,
//     crawler adds Jitter on top) and Jitter 2.0 (up to +2 s random)
//     produce an irregular 2.5–5 s cadence with no metronomic pattern;
//     ScanJavaScript false halves the request volume (no linked-script
//     or source-map fetches); RespectRobots false skips even the
//     robots.txt fetch. Combined with a browser UA + NinjaHeaders, the
//     crawl resembles a single human reader.
//   - Couverture: the same settings make a default 100-page budget
//     take on the order of 5–8 minutes; JS-bundled secrets are missed
//     entirely; and ignoring robots.txt is impolite at best — only
//     acceptable against targets you are explicitly authorized to test
//     (the future --ninja wiring must warn like --ignore-robots
//     does).
//
// Depth/MaxPages are left zero so the crawler defaults (2/100)
// apply; UserAgent is pinned once per call (see NinjaUserAgent).
// Safety is unaffected: SSRF guard and Scope enforcement are not
// part of ScanOptions and cannot be relaxed from here.
func NinjaDefaults() cerberus.ScanOptions {
	return cerberus.ScanOptions{
		UserAgent:      NinjaUserAgent(),
		RateLimit:      0.4,
		Jitter:         2.0,
		Concurrency:    1,
		RespectRobots:  false,
		ScanJavaScript: false,
		LowProfile:     true,
	}
}
