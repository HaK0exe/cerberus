// Package pipeline assembles the concrete Validator stack Sprint 3
// wires in front of internal/detector.Detector for the llm_review
// band: a primary backend (typically Ollama) with a secondary backend
// (typically llama.cpp) as a fallback — using composition, not a
// conditional branch — with each backend individually protected by its
// own internal/llm/circuitbreaker (per-call timeout + circuit
// breaker), and the whole chain wrapped in an internal/llm/cache-backed
// decorator so an identical candidate is never re-sent to a local
// model.
//
// None of the pieces this package assembles are implemented here: it
// only composes internal/llm/circuitbreaker, internal/llm/cache, and
// whatever cerberus.Validator implementations the caller passes in
// (internal/llm/ollama, internal/llm/llamacpp, or a test double).
package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/HaK0exe/cerberus/internal/llm"
	"github.com/HaK0exe/cerberus/internal/llm/cache"
	"github.com/HaK0exe/cerberus/internal/llm/circuitbreaker"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// Config configures New. Primary is required; every other field is
// optional.
type Config struct {
	// Primary is the first Validator tried for every call (typically an
	// *ollama.Validator). Required.
	Primary cerberus.Validator

	// Fallback, if non-nil, is tried when Primary fails (timeout,
	// circuit open, transport error, ...) — typically an
	// *llamacpp.Validator. Optional: a nil Fallback just means Primary
	// is the only backend in the chain.
	Fallback cerberus.Validator

	// Breaker tunes the circuitbreaker.Config each backend is
	// individually wrapped in. Zero value uses circuitbreaker's own
	// defaults (see circuitbreaker.Config.withDefaults).
	Breaker circuitbreaker.Config

	// Cache, if non-nil, is checked before Primary/Fallback are ever
	// called and updated after a successful call, so a candidate whose
	// (rule, path, redacted context, model, prompt version, rules
	// version) tuple was already validated recently short-circuits
	// straight to the cached verdict without another model call.
	// Optional: a nil Cache disables response caching.
	Cache llm.Cache

	// CacheKey derives cache lookup keys from an
	// llm.CacheKeyInput. Required whenever Cache is non-nil.
	CacheKey *cache.KeyDeriver

	// CacheTTLSeconds bounds how long a cached verdict is reused.
	// Ignored when Cache is nil. <= 0 disables caching even if Cache is
	// set, matching cache.MemCache's own "non-positive TTL is a no-op"
	// convention.
	CacheTTLSeconds int

	// ModelID, PromptVersion, and RulesVersion identify the exact
	// backend/template/ruleset combination in cache keys, so a change to
	// any of them naturally invalidates previously cached verdicts (see
	// internal/llm/cache.KeyDeriver.Derive).
	ModelID       string
	PromptVersion string
	RulesVersion  string
}

// New composes cfg into a single cerberus.Validator suitable for
// internal/detector.WithValidator: Primary and Fallback (each wrapped
// in its own timeout + circuit breaker) chained by composition, and —
// when Cache is configured — wrapped once more in a response cache.
//
// New never returns nil: at minimum the returned Validator wraps
// Primary in a circuit breaker, so callers always get the
// timeout/fallback safety net documented in internal/llm/circuitbreaker
// even with the simplest configuration.
func New(cfg Config) cerberus.Validator {
	var backends []cerberus.Validator
	if cfg.Primary != nil {
		backends = append(backends, circuitbreaker.New(cfg.Primary, cfg.Breaker))
	}
	if cfg.Fallback != nil {
		backends = append(backends, circuitbreaker.New(cfg.Fallback, cfg.Breaker))
	}

	var v cerberus.Validator = &chain{validators: backends}

	if cfg.Cache != nil && cfg.CacheKey != nil && cfg.CacheTTLSeconds > 0 {
		v = &cachingValidator{
			inner:         v,
			cache:         cfg.Cache,
			keys:          cfg.CacheKey,
			ttlSeconds:    cfg.CacheTTLSeconds,
			modelID:       cfg.ModelID,
			promptVersion: cfg.PromptVersion,
			rulesVersion:  cfg.RulesVersion,
			results:       make(map[string]cerberus.ValidationResult),
		}
	}

	return v
}

// chain tries each of its validators in order (composition, not a
// conditional): the first one to succeed wins. A validator "fails" for
// chain's purposes whenever it returns a non-nil error — in practice
// every backend here is wrapped in a circuitbreaker.Breaker, so that is
// always a circuitbreaker.ErrFallback-wrapped error, never a hang.
//
// If every validator fails, chain degrades to llm.FallbackResult, the
// same safe "uncertain" verdict a single failed Validator would
// produce, wrapped in circuitbreaker.ErrFallback so callers (e.g.
// internal/detector.Detector) can treat "no backend available" exactly
// like "the one configured backend failed".
type chain struct {
	validators []cerberus.Validator
}

var _ cerberus.Validator = (*chain)(nil)

func (c *chain) Validate(ctx context.Context, input cerberus.ValidationInput) (cerberus.ValidationResult, error) {
	var lastErr error
	for _, v := range c.validators {
		result, err := v.Validate(ctx, input)
		if err == nil {
			return result, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			// The caller gave up; don't keep trying further backends,
			// and don't mask its cancellation as a fallback.
			return cerberus.ValidationResult{}, ctxErr
		}
		lastErr = err
	}

	if lastErr == nil {
		// No backend configured at all.
		lastErr = circuitbreaker.ErrFallback
	}
	return llm.FallbackResult("pipeline: all validators exhausted"), errWrapFallback(lastErr)
}

// errWrapFallback ensures the error chain returns satisfies
// circuitbreaker.IsFallback, even if lastErr already does (in which
// case wrapping again is harmless — errors.Is still finds it).
func errWrapFallback(err error) error {
	if circuitbreaker.IsFallback(err) {
		return err
	}
	return &fallbackErr{err: err}
}

type fallbackErr struct{ err error }

func (e *fallbackErr) Error() string {
	return circuitbreaker.ErrFallback.Error() + ": " + e.err.Error()
}
func (e *fallbackErr) Unwrap() []error {
	return []error{circuitbreaker.ErrFallback, e.err}
}

// cachingValidator wraps inner with a response cache keyed on
// (rule, path, redacted context, model, prompt version, rules
// version), so an identical candidate seen again within the cache's
// TTL never reaches inner (and therefore never reaches the network)
// a second time.
//
// llm.Cache itself is a presence-only cache (Get reports hit/miss, Set
// records a hit — see internal/llm/cache's package doc) rather than a
// value store, so cachingValidator keeps the actual verdicts in a
// local, mutex-guarded map alongside it, using the same derived key.
// That mirrors how cache.MemCache is documented to be used today (an
// in-process, no-network-dependency cache for the "Local/CLI" topology
// in docs/architecture/overview.md); a future networked cache backend
// would need a paired value store, which is out of scope here.
type cachingValidator struct {
	inner cerberus.Validator
	cache llm.Cache
	keys  *cache.KeyDeriver

	ttlSeconds    int
	modelID       string
	promptVersion string
	rulesVersion  string

	mu      sync.Mutex
	results map[string]cerberus.ValidationResult
}

var _ cerberus.Validator = (*cachingValidator)(nil)

func (c *cachingValidator) Validate(ctx context.Context, input cerberus.ValidationInput) (cerberus.ValidationResult, error) {
	key := c.keys.Derive(llm.CacheKeyInput{
		CandidateFingerprint: candidateProxy(input),
		ContextHash:          contextHash(input.RedactedContext),
		ModelID:              c.modelID,
		PromptVersion:        c.promptVersion,
		RulesVersion:         c.rulesVersion,
	})

	if found, err := c.cache.Get(ctx, key); err == nil && found {
		c.mu.Lock()
		cached, ok := c.results[key]
		c.mu.Unlock()
		if ok {
			return cached, nil
		}
		// Presence recorded but no local verdict (e.g. a fresh process
		// against a previously-populated shared cache backend): fall
		// through and re-validate rather than fabricate a result.
	}

	result, err := c.inner.Validate(ctx, input)
	if err != nil {
		return result, err
	}

	c.mu.Lock()
	c.results[key] = result
	c.mu.Unlock()
	_ = c.cache.Set(ctx, key, c.ttlSeconds)

	return result, nil
}

// candidateProxy derives a stable per-candidate identity from the
// fields cerberus.ValidationInput actually carries. A Validator never
// sees the raw secret value or its fingerprint (see
// docs/architecture/llm-non-sovereign.md), so this is a proxy for
// "same rule, same file, same sanitized context" rather than the
// candidate's real cerberus.Finding.Fingerprint.
func candidateProxy(input cerberus.ValidationInput) string {
	h := sha256.Sum256([]byte(input.RuleID + "\x00" + input.Path))
	return hex.EncodeToString(h[:])
}

func contextHash(redactedContext string) string {
	h := sha256.Sum256([]byte(redactedContext))
	return hex.EncodeToString(h[:])
}
