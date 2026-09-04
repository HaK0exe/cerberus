package cache

import (
	"testing"

	"github.com/HaK0exe/cerberus/internal/llm"
)

func baseInput() llm.CacheKeyInput {
	return llm.CacheKeyInput{
		CandidateFingerprint: "cerberus:hmac-sha256:deadbeef",
		ContextHash:          "ctxhash1",
		ModelID:              "llama3.1:8b",
		PromptVersion:        "v1",
		RulesVersion:         "v3",
	}
}

func TestNewKeyDeriver_NoKey(t *testing.T) {
	if _, err := NewKeyDeriver(nil); err != ErrNoKey {
		t.Fatalf("expected ErrNoKey, got %v", err)
	}
	if _, err := NewKeyDeriver([]byte{}); err != ErrNoKey {
		t.Fatalf("expected ErrNoKey, got %v", err)
	}
}

func TestDerive_Deterministic(t *testing.T) {
	d, err := NewKeyDeriver([]byte("test-hmac-key"))
	if err != nil {
		t.Fatalf("NewKeyDeriver: %v", err)
	}

	in := baseInput()
	k1 := d.Derive(in)
	k2 := d.Derive(in)
	if k1 != k2 {
		t.Fatalf("identical inputs produced different keys: %q vs %q", k1, k2)
	}
}

func TestDerive_FieldChangeChangesKey(t *testing.T) {
	d, err := NewKeyDeriver([]byte("test-hmac-key"))
	if err != nil {
		t.Fatalf("NewKeyDeriver: %v", err)
	}

	base := d.Derive(baseInput())

	mutations := []func(*llm.CacheKeyInput){
		func(in *llm.CacheKeyInput) { in.CandidateFingerprint = "other-fp" },
		func(in *llm.CacheKeyInput) { in.ContextHash = "other-ctx" },
		func(in *llm.CacheKeyInput) { in.ModelID = "other-model" },
		func(in *llm.CacheKeyInput) { in.PromptVersion = "v2" },
		func(in *llm.CacheKeyInput) { in.RulesVersion = "v4" },
	}

	for i, mutate := range mutations {
		in := baseInput()
		mutate(&in)
		got := d.Derive(in)
		if got == base {
			t.Errorf("mutation %d: expected a different key, got the same one", i)
		}
	}
}

func TestDerive_NoFieldBoundaryCollision(t *testing.T) {
	d, err := NewKeyDeriver([]byte("test-hmac-key"))
	if err != nil {
		t.Fatalf("NewKeyDeriver: %v", err)
	}

	a := llm.CacheKeyInput{CandidateFingerprint: "a", ContextHash: "bc"}
	b := llm.CacheKeyInput{CandidateFingerprint: "ab", ContextHash: "c"}

	if d.Derive(a) == d.Derive(b) {
		t.Fatalf("field-boundary shift produced a colliding key")
	}
}

func TestDerive_DifferentKeysAreUnguessable(t *testing.T) {
	in := baseInput()

	d1, _ := NewKeyDeriver([]byte("hmac-key-one"))
	d2, _ := NewKeyDeriver([]byte("hmac-key-two"))

	k1 := d1.Derive(in)
	k2 := d2.Derive(in)

	if k1 == k2 {
		t.Fatalf("same input under two different HMAC keys produced the same cache key")
	}
}

func TestDerive_NotABareSHA256(t *testing.T) {
	// Guard against regressing to an unkeyed hash: a bare SHA256 of the
	// concatenated fields would be reproducible by anyone, with no key
	// at all. Derive requires a key to construct a KeyDeriver in the
	// first place (see TestNewKeyDeriver_NoKey), and the derived key
	// must carry the algorithm/key-space marker prefix.
	d, err := NewKeyDeriver([]byte("test-hmac-key"))
	if err != nil {
		t.Fatalf("NewKeyDeriver: %v", err)
	}

	got := d.Derive(baseInput())
	const wantPrefix = "cerberus:llm-cache:hmac-sha256:"
	if len(got) <= len(wantPrefix) || got[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("derived key %q missing expected prefix %q", got, wantPrefix)
	}
}
