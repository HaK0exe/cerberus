package mcp

import (
	"sync"
	"time"
)

// idleEvictAfter is how long a principal's bucket may sit untouched
// before it is evicted. It is kept far larger than any realistic
// refill time so eviction never discards state a still-active caller
// could observe: by the time a bucket goes idle this long it has long
// since refilled to a full burst anyway, so recreating it from
// scratch on the next call is indistinguishable from just leaving it
// in place.
const idleEvictAfter = 15 * time.Minute

// sweepInterval bounds how often Allow pays the cost of scanning the
// bucket map for eviction, so the map is swept periodically without
// doing it on every call.
const sweepInterval = 5 * time.Minute

// RateLimiter is a per-principal token bucket shared across every tool
// call, protecting the control plane from a runaway or compromised
// caller regardless of which specific tool it targets.
type RateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	rate      float64 // tokens replenished per second
	burst     float64 // bucket capacity, and the initial token count
	lastSweep time.Time
}

type bucket struct {
	tokens   float64
	lastFill time.Time
}

// NewRateLimiter builds a limiter allowing ratePerSecond sustained
// calls per principal, with a burst allowance of burst calls.
func NewRateLimiter(ratePerSecond, burst float64) *RateLimiter {
	return &RateLimiter{buckets: make(map[string]*bucket), rate: ratePerSecond, burst: burst}
}

// Allow reports whether principalID may make one more call right now,
// consuming a token if so.
func (rl *RateLimiter) Allow(principalID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rl.sweepLocked(now)

	b, ok := rl.buckets[principalID]
	if !ok {
		b = &bucket{tokens: rl.burst, lastFill: now}
		rl.buckets[principalID] = b
	}

	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.lastFill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweepLocked evicts buckets that have been idle long enough that
// their state carries no information a legitimate caller could still
// be relying on. Callers must hold rl.mu.
func (rl *RateLimiter) sweepLocked(now time.Time) {
	if now.Sub(rl.lastSweep) < sweepInterval {
		return
	}
	rl.lastSweep = now
	for id, b := range rl.buckets {
		if now.Sub(b.lastFill) >= idleEvictAfter {
			delete(rl.buckets, id)
		}
	}
}
