// Package policy implements the safe-handling invariants for secret
// values: fingerprinting, masking, and cache-key derivation. Nothing
// in this package ever returns or logs a raw secret value.
package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// ErrNoKey is returned when fingerprinting is attempted without a
// configured HMAC key. Cerberus refuses to fall back to an unkeyed
// hash: see docs/adr/0001-no-raw-secret-storage.md.
var ErrNoKey = errors.New("policy: no HMAC fingerprint key configured")

// Fingerprinter derives stable, non-reversible identifiers for secret
// values using a server-side HMAC key so findings can be deduplicated
// and re-identified without ever storing the raw value.
type Fingerprinter struct {
	key []byte
}

func NewFingerprinter(key []byte) (*Fingerprinter, error) {
	if len(key) == 0 {
		return nil, ErrNoKey
	}
	return &Fingerprinter{key: key}, nil
}

// Fingerprint returns "cerberus:hmac-sha256:<hex>" for value.
func (f *Fingerprinter) Fingerprint(value []byte) string {
	mac := hmac.New(sha256.New, f.key)
	mac.Write(value)
	return "cerberus:hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

// MaskedPrefix returns a human-readable, non-reversible hint such as
// "AKIA************" — at most visibleLen leading bytes, the rest
// replaced with asterisks.
func MaskedPrefix(value []byte, visibleLen int) string {
	if visibleLen > len(value) {
		visibleLen = len(value)
	}
	masked := make([]byte, len(value))
	copy(masked, value[:visibleLen])
	for i := visibleLen; i < len(value); i++ {
		masked[i] = '*'
	}
	return string(masked)
}

// Zero overwrites value in place. Callers must call this on every
// buffer that ever held a raw candidate/secret value once it is no
// longer needed (see memguard usage in later milestones for a stronger
// guarantee).
func Zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
