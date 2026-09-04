package web

import (
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/temoto/robotstxt"
)

// defaultUserAgent is the crawler's user agent when none is
// configured — self-identifying by default, per docs/security/ssrf.md
// and the transparent-crawler posture the rest of this package
// assumes (robots.txt honored, scope-bounded). Scan.Scan lets a caller
// override it (see ScanOptions.UserAgent) for engagements that need a
// different UA string; that is an explicit, per-run opt-in, never the
// default.
const defaultUserAgent = "CerberusBot"

// robotsCache fetches and caches robots.txt per host. A fetch failure
// fails safe (treated as "disallow nothing", per S2-07) rather than
// aborting the crawl.
type robotsCache struct {
	client    *http.Client
	userAgent string
	mu        sync.Mutex
	data      map[string]*robotstxt.RobotsData // host -> parsed robots.txt (nil = fetch failed, allow all)
	onWarn    func(format string, args ...any)
}

func newRobotsCache(client *http.Client, userAgent string, onWarn func(string, ...any)) *robotsCache {
	if onWarn == nil {
		onWarn = func(string, ...any) {}
	}
	if userAgent == "" {
		userAgent = defaultUserAgent
	}
	return &robotsCache{client: client, userAgent: userAgent, data: make(map[string]*robotstxt.RobotsData), onWarn: onWarn}
}

func (c *robotsCache) allowed(u *url.URL) bool {
	c.mu.Lock()
	data, cached := c.data[u.Host]
	c.mu.Unlock()

	if !cached {
		data = c.fetch(u)
		c.mu.Lock()
		c.data[u.Host] = data
		c.mu.Unlock()
	}

	if data == nil {
		// Fetch failed or robots.txt absent: fail safe, allow.
		return true
	}
	return data.TestAgent(u.Path, c.userAgent)
}

func (c *robotsCache) fetch(u *url.URL) *robotstxt.RobotsData {
	robotsURL := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/robots.txt"}
	req, err := http.NewRequest(http.MethodGet, robotsURL.String(), nil)
	if err != nil {
		c.onWarn("robots.txt fetch failed for %s: %v (failing open: allowing all paths)", u.Host, err)
		return nil
	}
	// Send the crawl's User-Agent so robots group matching and server
	// logs see the same identity as the crawl itself (previously this
	// fell back to Go-http-client/*).
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		c.onWarn("robots.txt fetch failed for %s: %v (failing open: allowing all paths)", u.Host, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil // no robots.txt: allow all
	}
	if resp.StatusCode != http.StatusOK {
		c.onWarn("robots.txt for %s returned HTTP %d (failing open: allowing all paths)", u.Host, resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRobotsBytes))
	if err != nil {
		c.onWarn("robots.txt for %s: reading body: %v (failing open: allowing all paths)", u.Host, err)
		return nil
	}

	data, err := robotstxt.FromBytes(body)
	if err != nil {
		c.onWarn("robots.txt for %s: parse error: %v (failing open: allowing all paths)", u.Host, err)
		return nil
	}
	return data
}

const maxRobotsBytes = 512 * 1024
