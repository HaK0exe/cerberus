package cache

import (
	"context"
	"sync"
	"time"
)

// clock is overridable in tests.
type clock func() time.Time

// MemCache is an in-memory, process-local implementation of
// llm.Cache. It is the default backend for local/CLI use
// (docs/architecture/overview.md's "Local/CLI" topology has no
// network dependency), and stores only cache keys and expiry times —
// never the CacheKeyInput fields or any Validator response payload
// itself, since llm.Cache is a boolean presence cache (Get reports
// hit/miss, Set records a hit), not a value store.
//
// MemCache is safe for concurrent use.
type MemCache struct {
	mu      sync.Mutex
	entries map[string]time.Time // key -> expiry
	now     clock
}

// NewMemCache returns an empty MemCache.
func NewMemCache() *MemCache {
	return &MemCache{
		entries: make(map[string]time.Time),
		now:     time.Now,
	}
}

// Get reports whether key is present and not expired.
func (c *MemCache) Get(ctx context.Context, key string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	expiry, ok := c.entries[key]
	if !ok {
		return false, nil
	}
	if c.now().After(expiry) {
		// Expired: evict lazily and report a miss.
		delete(c.entries, key)
		return false, nil
	}
	return true, nil
}

// Set records key as present for ttlSeconds seconds. ttlSeconds <= 0
// is treated as "already expired" (a no-op cache entry), so callers
// that pass a zero/negative TTL by mistake fail closed to a miss
// rather than caching forever.
func (c *MemCache) Set(ctx context.Context, key string, ttlSeconds int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if ttlSeconds <= 0 {
		delete(c.entries, key)
		return nil
	}
	c.entries[key] = c.now().Add(time.Duration(ttlSeconds) * time.Second)
	return nil
}

// Len returns the number of entries currently stored, including any
// not-yet-lazily-evicted expired ones. Exposed for tests/diagnostics
// only.
func (c *MemCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
