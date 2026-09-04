// Package cache implements the llm.Cache contract declared in
// internal/llm/validator.go: an in-memory response cache for local
// use (KeyDeriver + MemCache), plus a narrow, pluggable interface
// point for a future DynamoDB-backed implementation (table
// "cerberus-cache", Sprint 4).
//
// Cache keys are always derived via a server-side HMAC key, never a
// bare SHA256 of the CacheKeyInput fields — mirroring the
// policy.Fingerprinter convention (see internal/policy/fingerprint.go)
// so a cache key can never be recomputed, guessed, or correlated back
// to a candidate fingerprint by anyone without the HMAC key.
package cache

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/HaK0exe/cerberus/internal/llm"
)

// ErrNoKey is returned when a KeyDeriver is constructed without an
// HMAC key. Cerberus refuses to fall back to an unkeyed hash for cache
// keys, same as it does for candidate fingerprinting.
var ErrNoKey = errors.New("cache: no HMAC key configured")

// KeyDeriver turns a llm.CacheKeyInput into a stable, non-reversible,
// non-guessable cache key using a server-side HMAC key. Two identical
// inputs always derive the same key; changing any single field of the
// input changes the key.
type KeyDeriver struct {
	key []byte
}

// NewKeyDeriver returns a KeyDeriver using key as the HMAC key. key
// must be non-empty.
func NewKeyDeriver(key []byte) (*KeyDeriver, error) {
	if len(key) == 0 {
		return nil, ErrNoKey
	}
	return &KeyDeriver{key: key}, nil
}

// Derive returns "cerberus:llm-cache:hmac-sha256:<hex>" for in.
//
// Every field of in is written into the MAC with an explicit
// separator and length-prefix-free but unambiguous framing (each
// field is preceded by its own tag byte) so that, e.g.,
// CandidateFingerprint="a"+ContextHash="bc" can never collide with
// CandidateFingerprint="ab"+ContextHash="c".
func (d *KeyDeriver) Derive(in llm.CacheKeyInput) string {
	mac := hmac.New(sha256.New, d.key)
	writeField(mac, 'f', in.CandidateFingerprint)
	writeField(mac, 'c', in.ContextHash)
	writeField(mac, 'm', in.ModelID)
	writeField(mac, 'p', in.PromptVersion)
	writeField(mac, 'r', in.RulesVersion)
	return "cerberus:llm-cache:hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

// writeField writes an unambiguous framing of (tag, value) into h:
// a one-byte tag, the big-endian-free but fixed-width decimal length
// of value (using \x00 as a field terminator, which cannot appear in
// value since it is written byte-by-byte after the length), then the
// value itself.
func writeField(h interface {
	Write(p []byte) (int, error)
}, tag byte, value string) {
	_, _ = h.Write([]byte{tag})
	// Writing the length before the value prevents a boundary-shift
	// collision between adjacent variable-length fields (e.g. "a","bc"
	// vs "ab","c").
	length := uint32(len(value)) // #nosec G115 -- len() of an in-process string is never negative
	lenBytes := []byte{
		byte(length >> 24), // #nosec G115 -- intentional truncation to the low byte of each shifted window
		byte(length >> 16), // #nosec G115 -- intentional truncation to the low byte of each shifted window
		byte(length >> 8),  // #nosec G115 -- intentional truncation to the low byte of each shifted window
		byte(length),       // #nosec G115 -- intentional truncation to the low byte of each shifted window
	}
	_, _ = h.Write(lenBytes)
	_, _ = h.Write([]byte(value))
}
