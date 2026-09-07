// TLS fingerprint spoofing: some WAF/CDN stacks (Cloudflare, Akamai,
// Imperva) block on the TLS ClientHello shape (JA3) rather than — or
// in addition to — HTTP-level signals like User-Agent, because Go's
// crypto/tls produces a ClientHello no real browser sends (cipher
// suite order, extension order/set, no GREASE). Spoofing that shape
// with uTLS is a legitimate technique for an authorized engagement
// where a WAF's bot-management layer is itself in scope (or is simply
// getting in the way of testing what's behind it) — it changes what
// bytes go on the wire, nothing about SSRF/DNS validation below it.
package ssrf

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

// dialTLSWithFingerprint resolves+validates addr's host exactly like
// safeDialContext (same TOCTOU-closing dial-the-validated-IP
// discipline), then performs a TLS handshake shaped like hello
// instead of Go's native crypto/tls ClientHello.
//
// Returned as an http.Transport.DialTLSContext, this makes the
// Transport skip its own TLS handling entirely — including its
// automatic HTTP/2 negotiation, since DialTLSContext opts out of that
// (see net/http docs): whatever ALPN protocol actually gets
// negotiated in the handshake below, Transport will speak HTTP/1.1
// over the returned conn regardless. A stock Chrome/Firefox
// ClientHello advertises "h2" before "http/1.1" in ALPN, so left
// alone a real WAF/CDN would pick h2 and every request would then be
// HTTP/1.1 bytes sent over a connection the server expects to frame
// as HTTP/2 — every single fetch fails, not just the ones a WAF would
// actually block. So the ALPN extension is force-narrowed to
// ["http/1.1"] only, after uTLS has built the rest of the mimicked
// ClientHello. This doesn't change the JA3 fingerprint (JA3 hashes
// which extensions are present by ID, not the ALPN protocol list's
// contents), so it costs nothing on the anti-detection side.
func (g *Guard) dialTLSWithFingerprint(hello utls.ClientHelloID) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("ssrf: invalid address %q: %w", addr, err)
		}

		ip, err := g.ResolveValidated(ctx, host)
		if err != nil {
			return nil, err
		}

		dialer := &net.Dialer{Timeout: g.dialTimeout()}
		rawConn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err != nil {
			return nil, err
		}

		// ServerName is the original hostname (not the dialed IP), so
		// certificate verification checks against what the caller
		// actually asked for — same property safeDialContext gets for
		// free from http.Transport deriving ServerName off the
		// request URL; here we own the handshake, so we set it
		// ourselves.
		uConn := utls.UClient(rawConn, &utls.Config{ServerName: host, MinVersion: tls.VersionTLS12}, hello)
		if err := restrictALPNToHTTP1(uConn); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("ssrf: preparing tls fingerprint (%s) for %s: %w", hello.Client, host, err)
		}
		if err := uConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("ssrf: tls handshake (fingerprint %s) to %s: %w", hello.Client, host, err)
		}
		return uConn, nil
	}
}

// restrictALPNToHTTP1 builds uConn's mimicked ClientHello and, if it
// carries an ALPN extension, narrows it to offer only "http/1.1" —
// see dialTLSWithFingerprint's doc comment for why. A no-op if the
// mimicked hello has no ALPN extension at all.
func restrictALPNToHTTP1(uConn *utls.UConn) error {
	if err := uConn.BuildHandshakeState(); err != nil {
		return err
	}
	var found bool
	for _, ext := range uConn.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
			found = true
		}
	}
	if !found {
		return nil
	}
	// Re-applies uConn.Extensions to the internal handshake state and
	// re-marshals the ClientHello — required after mutating an
	// extension in place (see BuildHandshakeState's doc comment).
	return uConn.BuildHandshakeState()
}
