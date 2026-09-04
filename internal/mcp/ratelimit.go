package mcp

import (
	"sync"
	"time"
)

// RateLimiter is a per-principal token bucket shared across every tool
// call, protecting the control plane from a runaway or compromised
// caller regardless of which specific tool it targets.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens replenished per second
	burst   float64 // bucket capacity, and the initial token count
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
