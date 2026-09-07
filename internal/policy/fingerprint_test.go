package policy

import (
	"strings"
	"testing"
)

func TestNewFingerprinter_RejectsEmptyKey(t *testing.T) {
	if _, err := NewFingerprinter(nil); err == nil {
		t.Fatal("expected empty key to be rejected")
	}
	if _, err := NewFingerprinter([]byte{}); err == nil {
		t.Fatal("expected zero-length key to be rejected")
	}
}

func TestFingerprint_StableAndKeyed(t *testing.T) {
	a, _ := NewFingerprinter([]byte("key-one-12345678"))
	b, _ := NewFingerprinter([]byte("key-two-12345678"))

	fp1 := a.Fingerprint([]byte("secret-value"))
	fp2 := a.Fingerprint([]byte("secret-value"))
	if fp1 != fp2 {
		t.Fatal("same key+value must give stable fingerprint")
	}
	if fp1 == b.Fingerprint([]byte("secret-value")) {
		t.Fatal("different keys must give different fingerprints")
	}
	if a.Fingerprint([]byte("secret-1")) == a.Fingerprint([]byte("secret-2")) {
		t.Fatal("different values must give different fingerprints")
	}
	if !strings.HasPrefix(fp1, "cerberus:hmac-sha256:") {
		t.Fatalf("unexpected fingerprint format %q", fp1)
	}
}

func TestMaskedPrefix_NeverLeaksBeyondVisible(t *testing.T) {
	got := MaskedPrefix([]byte("AKIAEXAMPLE"), 4)
	if got != "AKIA*******" {
		t.Fatalf("got %q", got)
	}
	// visibleLen beyond length clamps, never panics.
	if got := MaskedPrefix([]byte("AB"), 10); got != "AB" {
		t.Fatalf("got %q", got)
	}
}

func TestZero_ClearsInPlace(t *testing.T) {
	buf := []byte("secret")
	Zero(buf)
	for _, b := range buf {
		if b != 0 {
			t.Fatal("expected buffer to be zeroed")
		}
	}
}
