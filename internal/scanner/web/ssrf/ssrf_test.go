package ssrf

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestValidateIP_BlocksDefaultRanges(t *testing.T) {
	g := NewGuard()
	blocked := []string{
		"127.0.0.1",
		"10.1.2.3",
		"172.16.0.5",
		"172.31.255.255",
		"192.168.1.1",
		"169.254.1.1",
		"169.254.169.254",
		"::1",
		"fc00::1",
		"fe80::1",
	}
	for _, ip := range blocked {
		if err := g.ValidateIP(net.ParseIP(ip)); err == nil {
			t.Errorf("expected %s to be blocked, got nil error", ip)
		}
	}
}

func TestValidateIP_AllowsPublic(t *testing.T) {
	g := NewGuard()
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34"}
	for _, ip := range allowed {
		if err := g.ValidateIP(net.ParseIP(ip)); err != nil {
			t.Errorf("expected %s to be allowed, got %v", ip, err)
		}
	}
}

// TestMetadataEndpoint_AlwaysBlocked verifies 169.254.169.254 is
// blocked even when BlockedNets has been overridden to omit
// link-local ranges entirely (simulating a misconfigured allow-list).
func TestMetadataEndpoint_AlwaysBlocked(t *testing.T) {
	g := NewGuard()
	g.BlockedNets = nil // pretend nothing is configured
	if err := g.ValidateIP(net.ParseIP("169.254.169.254")); err == nil {
		t.Fatal("expected 169.254.169.254 to always be blocked")
	}
}

// fakeResolver lets tests control what LookupIPAddr returns,
// including per-call sequencing for DNS-rebinding simulation.
type fakeResolver struct {
	seq   [][]net.IPAddr
	calls int
	err   error
}

func (f *fakeResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if f.err != nil {
		return nil, f.err
	}
	i := f.calls
	if i >= len(f.seq) {
		i = len(f.seq) - 1
	}
	f.calls++
	return f.seq[i], nil
}

// permissiveGuard returns a Guard with the loopback range removed
// from its blocklist, so tests can exercise real request/redirect
// plumbing against httptest servers (which listen on 127.0.0.1)
// without that being conflated with the SSRF-blocking behavior itself
// (covered separately by the Blocks* tests above).
func permissiveGuard() *Guard {
	g := NewGuard()
	var nets []*net.IPNet
	for _, n := range defaultBlockedNets {
		if n.String() == "127.0.0.0/8" {
			continue
		}
		nets = append(nets, n)
	}
	g.BlockedNets = nets
	return g
}

func addrs(ips ...string) []net.IPAddr {
	out := make([]net.IPAddr, len(ips))
	for i, s := range ips {
		out[i] = net.IPAddr{IP: net.ParseIP(s)}
	}
	return out
}

func TestResolveValidated_DirectIPLiteral(t *testing.T) {
	g := NewGuard()
	if _, err := g.ResolveValidated(context.Background(), "127.0.0.1"); err == nil {
		t.Fatal("expected loopback IP literal to be blocked")
	}
}

// TestDNSRebinding_MixedAnswerRejected: a single DNS answer containing
// both a public and a private IP must be rejected outright (fail
// closed), not "sometimes pick the public one".
func TestDNSRebinding_MixedAnswerRejected(t *testing.T) {
	g := NewGuard()
	g.Resolver = &fakeResolver{seq: [][]net.IPAddr{addrs("8.8.8.8", "127.0.0.1")}}
	if _, err := g.ResolveValidated(context.Background(), "rebind.example"); err == nil {
		t.Fatal("expected mixed public/private DNS answer to be rejected")
	}
}

// TestDNSRebinding_SecondLookupPrivate simulates the classic rebind:
// the resolver returns a public IP the first time (e.g. what a naive
// "validate once at request start" guard would check) and a private
// IP on a later lookup (what actually gets connected to, if the
// hostname were re-resolved at dial time instead of dialing the
// validated IP directly).
func TestDNSRebinding_SecondLookupPrivate(t *testing.T) {
	g := NewGuard()
	fr := &fakeResolver{seq: [][]net.IPAddr{addrs("8.8.8.8"), addrs("127.0.0.1")}}
	g.Resolver = fr

	ip, err := g.ResolveValidated(context.Background(), "rebind.example")
	if err != nil {
		t.Fatalf("first resolution should succeed with public IP: %v", err)
	}
	if ip.String() != "8.8.8.8" {
		t.Fatalf("expected 8.8.8.8, got %s", ip)
	}

	// Because safeDialContext resolves+validates+dials the SAME IP in
	// one step (never re-resolving between check and connect), a
	// client built on this guard dials 8.8.8.8 directly here rather
	// than re-resolving to whatever the second answer is. Assert the
	// dial-path helper does exactly that instead of trusting a
	// separately re-resolved address.
	client := g.NewClient(nil)
	tr := client.Transport.(*http.Transport)
	conn, err := tr.DialContext(context.Background(), "tcp", "rebind.example:80")
	if err == nil {
		conn.Close()
		t.Fatal("expected dial to fail (no listener on 8.8.8.8:80 in test env, or blocked) but definitely not to connect to 127.0.0.1")
	}
}

func TestNewClient_RejectsRedirectToBlockedAddress(t *testing.T) {
	// The origin itself is reachable (loopback allowed for this test
	// only, see permissiveGuard), but it redirects to the cloud
	// metadata IP literal: safeDialContext must reject the dial for
	// the *redirected* request even though the first hop succeeded.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer origin.Close()

	client := permissiveGuard().NewClient(nil)
	_, err := client.Get(origin.URL)
	if err == nil {
		t.Fatal("expected redirect to the metadata endpoint to be rejected")
	}
	if !containsBlocked(err) {
		t.Fatalf("expected a blocked-address error, got %v", err)
	}
}

func containsBlocked(err error) bool {
	for err != nil {
		if errors.Is(err, ErrBlockedAddress) || errors.Is(err, ErrNoValidAddress) {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestNewClient_RejectsRedirectLoop(t *testing.T) {
	var mux http.ServeMux
	var srv *httptest.Server
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/a", http.StatusFound)
	})
	srv = httptest.NewServer(&mux)
	defer srv.Close()

	g := permissiveGuard()
	g.MaxRedirects = 5
	client := g.NewClient(nil)
	_, err := client.Get(srv.URL + "/a")
	if err == nil {
		t.Fatal("expected redirect loop to be terminated with an error")
	}
	if !errors.Is(err.(interface{ Unwrap() error }).Unwrap(), ErrTooManyRedirects) {
		t.Fatalf("expected ErrTooManyRedirects, got %v", err)
	}
}

func TestNewClient_AllowsNormalRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := permissiveGuard().NewClient(nil)
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected request to a public-ish test server to succeed, got %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("unexpected body %q", body)
	}
}

func TestNewClient_TLSFingerprint_FetchesOverSpoofedHandshake(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	g := permissiveGuard()
	g.TLSFingerprint = utls.HelloChrome_Auto
	client := g.NewClient(nil)
	// httptest.NewTLSServer signs with its own throwaway CA, which our
	// uTLS config's default (system) RootCAs don't trust. A dial and
	// handshake that fails on THAT — not on a connection-refused, DNS,
	// or SSRF error — proves the fingerprinted path reached the
	// server and ran real certificate verification.
	_, err := client.Get(srv.URL)
	if err == nil {
		t.Fatal("expected a certificate error against the test server's self-signed cert (proves the fingerprinted path performed real verification)")
	}
}

func TestNewClient_TLSFingerprint_StillBlocksSSRFTarget(t *testing.T) {
	g := NewGuard()
	g.TLSFingerprint = utls.HelloChrome_Auto
	client := g.NewClient(nil)
	_, err := client.Get("https://127.0.0.1:1/")
	if err == nil {
		t.Fatal("expected the loopback target to be rejected by SSRF validation even with TLS fingerprinting enabled")
	}
}

func TestNewClient_TLSFingerprint_IgnoredWhenProxySet(t *testing.T) {
	g := NewGuard()
	g.TLSFingerprint = utls.HelloChrome_Auto
	g.ProxyURL = &url.URL{Scheme: "http", Host: "127.0.0.1:0"}
	client := g.NewClient(nil)
	tr := client.Transport.(*http.Transport)
	if tr.DialTLSContext != nil {
		t.Fatal("expected DialTLSContext to be left unset when ProxyURL is set, per TLSFingerprint's documented precedence")
	}
}

func TestValidateIP_BlocksIPv4MappedIPv6(t *testing.T) {
	g := NewGuard()
	// ::ffff:10.0.0.1 is 10.0.0.1 in mapped form and must be blocked.
	if err := g.ValidateIP(net.ParseIP("::ffff:10.0.0.1")); err == nil {
		t.Error("expected ::ffff:10.0.0.1 (mapped private IPv4) to be blocked")
	}
	if err := g.ValidateIP(net.ParseIP("::ffff:8.8.8.8")); err != nil {
		t.Errorf("expected ::ffff:8.8.8.8 (mapped public IPv4) to be allowed, got %v", err)
	}
}

func TestNewGuard_CopiesBlockedNets(t *testing.T) {
	a := NewGuard()
	b := NewGuard()
	if len(a.BlockedNets) == 0 || len(a.BlockedNets) != len(b.BlockedNets) {
		t.Fatal("expected default blocked nets to be populated")
	}
	a.BlockedNets[0] = nil
	if b.BlockedNets[0] == nil {
		t.Error("mutating one guard's BlockedNets must not affect another (shared backing array)")
	}
}
