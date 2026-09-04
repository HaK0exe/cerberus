package mcp

import (
	"testing"
	"time"
)

func TestRateLimiter_Allow_BasicBurstAndRefill(t *testing.T) {
	rl := NewRateLimiter(1, 2)

	first := rl.Allow("p1")
	second := rl.Allow("p1")
	if !first || !second {
		t.Fatal("expected the first 2 calls (burst) to be allowed")
	}
	if rl.Allow("p1") {
		t.Fatal("expected the 3rd immediate call to be denied")
	}
}

func TestRateLimiter_IdleBucketsAreEvicted(t *testing.T) {
	rl := NewRateLimiter(1, 1)

	if !rl.Allow("stale") {
		t.Fatal("expected the first call for a new principal to be allowed")
	}
	if _, ok := rl.buckets["stale"]; !ok {
		t.Fatal("expected a bucket to exist for the principal right after Allow")
	}

	// Backdate the bucket and the last-sweep clock so the next Allow
	// call (for a different principal) triggers a sweep that finds
	// "stale" past idleEvictAfter.
	rl.mu.Lock()
	rl.buckets["stale"].lastFill = time.Now().Add(-2 * idleEvictAfter)
	rl.lastSweep = time.Now().Add(-2 * sweepInterval)
	rl.mu.Unlock()

	rl.Allow("other")

	rl.mu.Lock()
	_, stillPresent := rl.buckets["stale"]
	rl.mu.Unlock()
	if stillPresent {
		t.Error("expected the idle bucket to be evicted by the sweep")
	}
}

func TestRateLimiter_RecentBucketsSurviveASweep(t *testing.T) {
	rl := NewRateLimiter(1, 1)

	rl.Allow("active")

	rl.mu.Lock()
	rl.lastSweep = time.Now().Add(-2 * sweepInterval) // force a sweep to run
	rl.mu.Unlock()

	rl.Allow("other")

	rl.mu.Lock()
	_, stillPresent := rl.buckets["active"]
	rl.mu.Unlock()
	if !stillPresent {
		t.Error("a recently-used bucket must not be evicted by a sweep")
	}
}
