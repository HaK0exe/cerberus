package cache

import (
	"context"
	"testing"
	"time"

	"github.com/HaK0exe/cerberus/internal/llm"
)

// var assertion: MemCache must satisfy llm.Cache.
var _ llm.Cache = (*MemCache)(nil)

func TestMemCache_MissThenHit(t *testing.T) {
	c := NewMemCache()
	ctx := context.Background()

	found, err := c.Get(ctx, "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Fatalf("expected miss before Set")
	}

	if err := c.Set(ctx, "k1", 60); err != nil {
		t.Fatalf("Set: %v", err)
	}

	found, err = c.Get(ctx, "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatalf("expected hit after Set")
	}
}

func TestMemCache_TTLExpiry(t *testing.T) {
	c := NewMemCache()
	now := time.Now()
	c.now = func() time.Time { return now }

	ctx := context.Background()
	if err := c.Set(ctx, "k1", 5); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Just before expiry: still a hit.
	now = now.Add(4 * time.Second)
	found, err := c.Get(ctx, "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatalf("expected hit before TTL elapses")
	}

	// Past expiry: now a miss.
	now = now.Add(2 * time.Second)
	found, err = c.Get(ctx, "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Fatalf("expected miss after TTL elapses")
	}

	if got := c.Len(); got != 0 {
		t.Fatalf("expected expired entry to be evicted, Len()=%d", got)
	}
}

func TestMemCache_NonPositiveTTLIsNoop(t *testing.T) {
	c := NewMemCache()
	ctx := context.Background()

	if err := c.Set(ctx, "k1", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	found, err := c.Get(ctx, "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Fatalf("expected zero-TTL Set to not produce a hit")
	}

	if err := c.Set(ctx, "k2", -1); err != nil {
		t.Fatalf("Set: %v", err)
	}
	found, err = c.Get(ctx, "k2")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Fatalf("expected negative-TTL Set to not produce a hit")
	}
}

func TestMemCache_DistinctKeysDoNotCollide(t *testing.T) {
	c := NewMemCache()
	ctx := context.Background()

	if err := c.Set(ctx, "k1", 60); err != nil {
		t.Fatalf("Set: %v", err)
	}

	found, err := c.Get(ctx, "k2")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Fatalf("expected miss for an unrelated key")
	}
}

func TestMemCache_ContextCanceled(t *testing.T) {
	c := NewMemCache()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := c.Get(ctx, "k1"); err == nil {
		t.Fatalf("expected error from Get with a canceled context")
	}
	if err := c.Set(ctx, "k1", 60); err == nil {
		t.Fatalf("expected error from Set with a canceled context")
	}
}

func TestMemCache_EndToEndWithKeyDeriver(t *testing.T) {
	d, err := NewKeyDeriver([]byte("test-hmac-key"))
	if err != nil {
		t.Fatalf("NewKeyDeriver: %v", err)
	}
	c := NewMemCache()
	ctx := context.Background()

	in := llm.CacheKeyInput{
		CandidateFingerprint: "cerberus:hmac-sha256:aaaa",
		ContextHash:          "ctx-1",
		ModelID:              "llama3.1:8b",
		PromptVersion:        "v1",
		RulesVersion:         "v3",
	}
	key := d.Derive(in)

	found, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Fatalf("expected miss before Set")
	}

	if err := c.Set(ctx, key, 30); err != nil {
		t.Fatalf("Set: %v", err)
	}

	found, err = c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatalf("expected hit after Set")
	}

	// Changing any single input field must miss the cache.
	other := in
	other.ModelID = "llama3.1:70b"
	otherKey := d.Derive(other)

	found, err = c.Get(ctx, otherKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Fatalf("expected miss for a different model ID")
	}
}
