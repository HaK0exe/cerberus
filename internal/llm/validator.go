// Package llm hosts cerberus.Validator implementations (Ollama,
// llama.cpp — Sprint 3, not yet implemented) plus the shared
// context-sanitizer, prompt templating, and response cache used by all
// of them.
//
// Invariant: a Validator can only shift a score within the
// [ThresholdLLMReview, ThresholdFinding) band; it is never authoritative
// and never receives a raw secret value, only redacted context. See
// docs/architecture/llm-non-sovereign.md.
package llm

import "context"

// Sanitize strips a candidate's raw secret value from freeform context
// text before it is ever sent to a Validator, replacing it with a
// fixed-width placeholder so length/positioning artifacts don't leak
// exploitable information either.
func Sanitize(context string, secretValue []byte) string {
	// Placeholder implementation for the scaffold: Sprint 3 replaces
	// this with a proper tokenizer-aware redaction pass.
	return context
}

// CacheKeyInput is hashed (HMAC, never a bare SHA256 — see
// docs/architecture/llm-cache.md) to form a Validator response cache
// key.
type CacheKeyInput struct {
	CandidateFingerprint string
	ContextHash          string
	ModelID              string
	PromptVersion        string
	RulesVersion         string
}

// Cache is the Validator response cache contract.
type Cache interface {
	Get(ctx context.Context, key string) (found bool, err error)
	Set(ctx context.Context, key string, ttlSeconds int) error
}
