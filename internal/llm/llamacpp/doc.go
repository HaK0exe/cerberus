// Package llamacpp implements cerberus.Validator against a llama.cpp
// server's OpenAI-compatible HTTP API (typically http://localhost:8080),
// selectable as a fallback when Ollama (internal/llm/ollama) is
// unavailable — see issue S3-02 (#15).
//
// Like every Validator, it is never sovereign: it renders a prompt from
// a pre-sanitized cerberus.ValidationInput (see internal/llm.Sanitize
// and docs/architecture/llm-non-sovereign.md) via a versioned template
// from internal/llm/prompt, sends it to the configured server, and
// parses the response with internal/llm.ParseValidationResultWithRetry
// — it never invents its own JSON parsing that would bypass that
// schema, and it never receives or logs a raw secret value.
package llamacpp
