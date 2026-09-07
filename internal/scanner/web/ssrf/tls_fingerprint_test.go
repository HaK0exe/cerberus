package ssrf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestRestrictALPNToHTTP1_NegotiatesHTTP1EvenWhenServerPrefersH2 is a
// regression test for the bug where enabling TLS fingerprinting broke
// every single request: uTLS's mimicked ClientHello (like a real
// browser's) advertises ALPN "h2" ahead of "http/1.1", so a real
// server picks h2 — but http.Transport, once DialTLSContext is set,
// always speaks HTTP/1.1 over the returned connection regardless of
// what was actually negotiated (see dialTLSWithFingerprint's doc
// comment). Sending HTTP/1.1 bytes over a connection the server
// framed as HTTP/2 fails every request, indistinguishable from being
// blocked. restrictALPNToHTTP1 must force the negotiated protocol
// down to http/1.1 so Transport's assumption holds.
func TestRestrictALPNToHTTP1_NegotiatesHTTP1EvenWhenServerPrefersH2(t *testing.T) {
	cert := selfSignedCert(t)

	// Real loopback TCP, not net.Pipe: net.Pipe is unbuffered/fully
	// synchronous and a full TLS handshake's read/write pattern
	// deadlocks on it (each side can block trying to write while the
	// other is also blocked writing) — a real socket has kernel-level
	// buffering that avoids that class of test-only deadlock.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"}, // a real server's preference order
	}
	serverState := make(chan tls.ConnectionState, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		sConn := tls.Server(conn, serverCfg)
		if err := sConn.Handshake(); err != nil {
			serverErr <- err
			return
		}
		serverState <- sConn.ConnectionState()
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	uConn := utls.UClient(clientConn, &utls.Config{ServerName: "example.com", InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	if err := restrictALPNToHTTP1(uConn); err != nil {
		t.Fatalf("restrictALPNToHTTP1: %v", err)
	}
	if err := uConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if got := uConn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("client negotiated protocol = %q, want http/1.1", got)
	}

	select {
	case err := <-serverErr:
		t.Fatalf("server handshake failed: %v", err)
	case st := <-serverState:
		if st.NegotiatedProtocol != "http/1.1" {
			t.Fatalf("server negotiated protocol = %q, want http/1.1 (a real WAF/CDN would have picked h2 here, breaking every request)", st.NegotiatedProtocol)
		}
	}
}

// TestRestrictALPNToHTTP1_NoopWithoutALPNExtension guards the other
// branch: a mimicked hello with no ALPN extension at all must not
// error.
func TestRestrictALPNToHTTP1_NoopWithoutALPNExtension(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	uConn := utls.UClient(clientConn, &utls.Config{ServerName: "example.com"}, utls.HelloGolang)
	if err := restrictALPNToHTTP1(uConn); err != nil {
		t.Fatalf("restrictALPNToHTTP1 on HelloGolang: %v", err)
	}
}
