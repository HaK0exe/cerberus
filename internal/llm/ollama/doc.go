// Package ollama implements cerberus.Validator against a local Ollama
// instance (Sprint 3, issue #14 / S3-01).
//
// A Validator built by this package sends only
// cerberus.ValidationInput.RedactedContext (already stripped of any
// raw secret value by llm.Sanitize before it ever reaches here) — see
// docs/architecture/llm-non-sovereign.md. It renders the request with
// the versioned "candidate_validation" template from internal/llm/prompt,
// calls Ollama's HTTP generate API, and parses the model's response with
// internal/llm.ParseValidationResultWithRetry so every response is
// subject to the same strict schema every Validator implementation must
// honor. It never runs its own ad hoc JSON parsing of a model's output.
//
// Validate is a thin, composable cerberus.Validator: it does not embed
// a cache or a circuit breaker itself. Response caching
// (internal/llm/cache) and per-call timeout/circuit-breaking
// (internal/llm/circuitbreaker) are wired around it elsewhere (issue
// #21), so a Validator built by New can be wrapped by either decorator
// without modification.
package ollama
