package web

import (
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/temoto/robotstxt"
)

// robotsUserAgent is the crawler's user agent, used both for the
// User-Agent header and for matching robots.txt group rules.
const robotsUserAgent = "CerberusBot"

// robotsCache fetches and caches robots.txt per host. A fetch failure
// fails safe (treated as "disallow nothing", per S2-07) rather than
// aborting the crawl.
type robotsCache struct {
	client *http.Client
	mu     sync.Mutex
	data   map[string]*robotstxt.RobotsData // host -> parsed robots.txt (nil = fetch failed, allow all)
	onWarn func(format string, args ...any)
}

func newRobotsCache(client *http.Client, onWarn func(string, ...any)) *robotsCache {
	if onWarn == nil {
		onWarn = func(string, ...any) {}
	}
	return &robotsCache{client: client, data: make(map[string]*robotstxt.RobotsData), onWarn: onWarn}
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
	return data.TestAgent(u.Path, robotsUserAgent)
}

func (c *robotsCache) fetch(u *url.URL) *robotstxt.RobotsData {
	robotsURL := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/robots.txt"}
	resp, err := c.client.Get(robotsURL.String())
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
