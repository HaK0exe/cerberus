// Package ssrf implements the SSRF guard required by every outbound
// HTTP client in internal/scanner/web: DNS resolution and IP
// validation before the initial request, re-validated on every
// redirect hop. See docs/security/ssrf.md — this package is the
// concrete implementation of that spec.
//
// The core defense is at dial time: the guard resolves the hostname,
// validates every candidate IP against the blocklist, and then dials
// the validated IP address directly (never the hostname again). Since
// Go's net/http calls DialContext once per connection — including one
// per redirect hop, because a redirect is a brand new request — this
// single choke point re-validates on every hop for free and closes
// the classic "check the hostname, then let the stdlib re-resolve
// and connect to whatever DNS says now" TOCTOU/rebinding gap.
package ssrf

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// ErrBlockedAddress is returned (wrapped) when a resolved IP falls
// inside a blocked range.
var ErrBlockedAddress = errors.New("ssrf: target address is blocked")

// ErrNoValidAddress is returned when a hostname resolves but none of
// its addresses pass validation.
var ErrNoValidAddress = errors.New("ssrf: no valid (non-blocked) address for host")

// ErrTooManyRedirects is returned when a redirect chain exceeds the
// configured hop limit.
var ErrTooManyRedirects = errors.New("ssrf: too many redirects")

// metadataIP is the cloud instance metadata endpoint. It is always
// blocked, regardless of any user-supplied allow-list.
var metadataIP = net.ParseIP("169.254.169.254")

// DefaultBlockedCIDRs is the default-blocked range list from
// docs/security/ssrf.md.
var DefaultBlockedCIDRs = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(fmt.Sprintf("ssrf: invalid default CIDR %q: %v", c, err))
		}
		nets = append(nets, n)
	}
	return nets
}

var defaultBlockedNets = mustParseCIDRs(DefaultBlockedCIDRs)

// Resolver is the DNS lookup interface the guard depends on. It is
// satisfied by *net.Resolver; tests substitute a fake to simulate DNS
// rebinding (return a public IP on the first lookup, a private IP on
// a later one).
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Guard validates hostnames/IPs before they may be dialed and
// produces an *http.Client whose every connection (initial request
// and every redirect hop) is routed through that validation.
type Guard struct {
	// Resolver performs DNS lookups. Defaults to net.DefaultResolver.
	Resolver Resolver
	// BlockedNets overrides the default blocked ranges. Defaults to
	// DefaultBlockedCIDRs when nil.
	BlockedNets []*net.IPNet
	// MaxRedirects bounds the length of a redirect chain. Defaults to
	// 10 when zero.
	MaxRedirects int
	// DialTimeout bounds a single connection attempt.
	DialTimeout time.Duration
}

// NewGuard returns a Guard configured with the package defaults.
func NewGuard() *Guard {
	return &Guard{
		Resolver:     net.DefaultResolver,
		BlockedNets:  defaultBlockedNets,
		MaxRedirects: 10,
		DialTimeout:  10 * time.Second,
	}
}

func (g *Guard) blockedNets() []*net.IPNet {
	if len(g.BlockedNets) > 0 {
		return g.BlockedNets
	}
	return defaultBlockedNets
}

func (g *Guard) resolver() Resolver {
	if g.Resolver != nil {
		return g.Resolver
	}
	return net.DefaultResolver
}

// ValidateIP reports an error if ip falls inside a blocked range. The
// cloud metadata address (169.254.169.254) is always blocked, even if
// BlockedNets has been overridden to omit link-local ranges.
func (g *Guard) ValidateIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("ssrf: nil IP")
	}
	if ip.Equal(metadataIP) {
		return fmt.Errorf("%w: %s (cloud metadata endpoint)", ErrBlockedAddress, ip)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, ip)
	}
	for _, n := range g.blockedNets() {
		if n.Contains(ip) {
			return fmt.Errorf("%w: %s (in %s)", ErrBlockedAddress, ip, n)
		}
	}
	return nil
}

// ResolveValidated resolves host and returns the first IP that passes
// validation, erroring if none do (i.e. the hostname is entirely
// blocked, not merely "one of several addresses is blocked" — a host
// that round-robins between a public and a private IP must not be
// treated as safe just because one lookup returned a public address).
func (g *Guard) ResolveValidated(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if err := g.ValidateIP(ip); err != nil {
			return nil, err
		}
		return ip, nil
	}

	addrs, err := g.resolver().LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("ssrf: resolving %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("ssrf: %s resolved to no addresses", host)
	}

	var chosen net.IP
	for _, a := range addrs {
		if err := g.ValidateIP(a.IP); err != nil {
			// Fail closed: a host with ANY blocked address is
			// rejected outright rather than silently skipped, to
			// defeat DNS-rebinding setups that mix a public and a
			// private answer in the same response.
			return nil, fmt.Errorf("%w: %s", ErrNoValidAddress, err)
		}
		if chosen == nil {
			chosen = a.IP
		}
	}
	return chosen, nil
}

// safeDialContext resolves+validates addr's host and dials the
// validated IP directly (never re-resolving the hostname at connect
// time), closing the classic check-then-connect TOCTOU window.
func (g *Guard) safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("ssrf: invalid address %q: %w", addr, err)
	}

	ip, err := g.ResolveValidated(ctx, host)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: g.DialTimeout}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
}

// NewClient returns an *http.Client whose every connection — the
// initial request and every redirect hop — is dialed through
// safeDialContext, and whose redirect chain is bounded. extraCheck, if
// non-nil, is invoked for every redirect target in addition to the
// SSRF validation (used by the crawler to enforce crawl scope).
func (g *Guard) NewClient(extraCheck func(req *http.Request) error) *http.Client {
	transport := &http.Transport{
		DialContext: g.safeDialContext,
		// TLSClientConfig is left default (empty): http.Transport
		// derives ServerName from the request URL's hostname, not
		// from the dialed IP, so certificate validation still checks
		// against the real hostname.
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	maxRedirects := g.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 10
	}

	return &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return ErrTooManyRedirects
			}
			if extraCheck != nil {
				if err := extraCheck(req); err != nil {
					return err
				}
			}
			// No explicit IP/DNS re-validation here: it happens
			// unconditionally in safeDialContext for this redirected
			// request too, since Transport dials fresh per request.
			return nil
		},
	}
}
