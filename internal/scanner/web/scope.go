package web

import (
	"net/url"
	"strings"
)

// Scope enforces --allowed-domains and --exclude-path. It is checked
// both when a link is discovered (so we never even enqueue an
// out-of-scope URL) and inside the SSRF client's CheckRedirect (so a
// redirect cannot be used to escape scope either — see S2-08).
type Scope struct {
	AllowedDomains []string
	ExcludePaths   []string
}

// Allowed reports whether u may be fetched under this scope.
func (s Scope) Allowed(u *url.URL) bool {
	if u == nil {
		return false
	}
	if !s.domainAllowed(u.Hostname()) {
		return false
	}
	if s.pathExcluded(u.Path) {
		return false
	}
	return true
}

func (s Scope) domainAllowed(host string) bool {
	if len(s.AllowedDomains) == 0 {
		return true
	}
	host = strings.ToLower(host)
	for _, d := range s.AllowedDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if host == d {
			return true
		}
		// Allow explicit subdomains of an allowed domain (foo.example.com
		// for example.com) but never the reverse — an allowed subdomain
		// must not authorize its parent or unrelated siblings.
		if strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func (s Scope) pathExcluded(path string) bool {
	for _, p := range s.ExcludePaths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Boundary-aware prefix: "/api" excludes "/api" and "/api/...",
		// but not "/apiv2". A trailing "/" in the pattern ("api/")
		// already implies a directory boundary.
		if path == p {
			return true
		}
		base := strings.TrimSuffix(p, "/")
		if strings.HasPrefix(path, base+"/") {
			return true
		}
	}
	return false
}
