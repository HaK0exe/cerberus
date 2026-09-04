package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// ErrSchemaViolation is wrapped by every error ParseValidationResult
// returns for malformed or schema-violating model output, so callers
// can distinguish "the model returned something that isn't a valid
// cerberus.ValidationResult" from other failure modes (transport
// errors, context cancellation, ...) with errors.Is, without string
// matching.
var ErrSchemaViolation = errors.New("llm: response violates validation result schema")

// validClassifications is the closed set of values
// cerberus.ValidationClassification is allowed to take. A Validator
// is never sovereign (docs/architecture/llm-non-sovereign.md): an
// unrecognized classification string is treated the same as any other
// schema violation, never coerced into a guess.
var validClassifications = map[cerberus.ValidationClassification]struct{}{
	cerberus.ClassificationLikelySecret:   {},
	cerberus.ClassificationLikelyFalsePos: {},
	cerberus.ClassificationUncertain:      {},
}

// schemaResult mirrors the JSON shape a Validator is required to
// return. Fields are pointers so a key that is entirely absent can be
// told apart from one present with its Go zero value (e.g.
// "confidence": 0), and DisallowUnknownFields (set where this is
// decoded) rejects any field the schema does not define.
type schemaResult struct {
	Classification *string  `json:"classification"`
	Confidence     *float64 `json:"confidence"`
	Reason         *string  `json:"reason"`
}

// ParseValidationResult parses and strictly validates raw bytes
// (typically a local LLM's raw response body) against the
// classification/confidence/reason JSON schema required of every
// cerberus.ValidationResult, per issue S3-05 ("LLM: structured JSON
// output + schema validation").
//
// It is strict on purpose: exactly the three documented fields, all
// required, classification restricted to the closed
// cerberus.ValidationClassification enum, confidence a finite JSON
// number, and no trailing data after the JSON object. Any violation
// returns an error wrapping ErrSchemaViolation and a zero-value
// ValidationResult — callers must never treat that zero value as a
// trustworthy result. Confidence outside [0, 1] is not a schema
// violation: it is clamped into range, per the documented policy (see
// ParseValidationResultWithRetry for the retry/degrade policy malformed
// output is subject to).
func ParseValidationResult(raw []byte) (cerberus.ValidationResult, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return cerberus.ValidationResult{}, fmt.Errorf("%w: empty response", ErrSchemaViolation)
	}

	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()

	var parsed schemaResult
	if err := dec.Decode(&parsed); err != nil {
		return cerberus.ValidationResult{}, fmt.Errorf("%w: invalid JSON: %v", ErrSchemaViolation, err)
	}
	// A model that echoes extra tokens after the object (a trailing
	// explanation, a second object, ...) is not a valid single JSON
	// value for this schema.
	if dec.More() {
		return cerberus.ValidationResult{}, fmt.Errorf("%w: trailing data after JSON object", ErrSchemaViolation)
	}

	switch {
	case parsed.Classification == nil:
		return cerberus.ValidationResult{}, fmt.Errorf("%w: missing required field %q", ErrSchemaViolation, "classification")
	case parsed.Confidence == nil:
		return cerberus.ValidationResult{}, fmt.Errorf("%w: missing required field %q", ErrSchemaViolation, "confidence")
	case parsed.Reason == nil:
		return cerberus.ValidationResult{}, fmt.Errorf("%w: missing required field %q", ErrSchemaViolation, "reason")
	}

	classification := cerberus.ValidationClassification(*parsed.Classification)
	if _, ok := validClassifications[classification]; !ok {
		return cerberus.ValidationResult{}, fmt.Errorf("%w: invalid classification %q", ErrSchemaViolation, *parsed.Classification)
	}

	confidence := *parsed.Confidence
	if math.IsNaN(confidence) || math.IsInf(confidence, 0) {
		// Not reachable for most JSON decoders on well-formed input,
		// but a decimal literal with an extreme exponent (e.g.
		// "1e400") is valid JSON that overflows float64 to +Inf, so
		// this is a real case, not just defensive noise.
		return cerberus.ValidationResult{}, fmt.Errorf("%w: confidence is not a finite number", ErrSchemaViolation)
	}

	return cerberus.ValidationResult{
		Classification: classification,
		Confidence:     clampConfidence(confidence),
		Reason:         *parsed.Reason,
	}, nil
}

// clampConfidence clamps c into [0, 1], per issue S3-05's acceptance
// criterion that confidence is always clamped to that range rather
// than rejected as a schema violation.
func clampConfidence(c float64) float64 {
	switch {
	case c < 0:
		return 0
	case c > 1:
		return 1
	default:
		return c
	}
}

// Attempt produces one raw candidate response for
// ParseValidationResultWithRetry to validate — typically a closure
// around a single call into a Validator's underlying model runtime
// (Ollama, llama.cpp, ...).
type Attempt func(ctx context.Context) ([]byte, error)

// FallbackResult is the safe, non-authoritative result the LLM stage
// degrades to when no schema-valid response could be obtained. It
// always reports cerberus.ClassificationUncertain at confidence 0, so
// a caller folding it into a deterministic score can never have it
// move the score in either direction — consistent with
// docs/architecture/llm-non-sovereign.md: the LLM stage failing closed
// must never be worse than the LLM stage being skipped entirely.
func FallbackResult(reason string) cerberus.ValidationResult {
	return cerberus.ValidationResult{
		Classification: cerberus.ClassificationUncertain,
		Confidence:     0,
		Reason:         reason,
	}
}

// ParseValidationResultWithRetry implements Cerberus's documented
// malformed-output policy for LLM Validators (issue S3-05 / #18):
// call attempt up to maxAttempts times (maxAttempts <= 0 is treated as
// 1), validating each raw response against the strict schema via
// ParseValidationResult. The first schema-valid response is returned
// immediately.
//
// Malformed or schema-violating output must never crash or block the
// detection pipeline. So if every attempt fails — whether attempt
// itself errored (e.g. the model runtime timed out) or every response
// it did produce failed schema validation — this returns
// FallbackResult, a safe "uncertain" ValidationResult, alongside a
// non-nil error describing the last failure. The returned
// ValidationResult is always safe for a caller to use whether or not
// err is nil; err is provided for logging/observability, not because
// the result is untrustworthy without checking it first.
func ParseValidationResultWithRetry(ctx context.Context, maxAttempts int, attempt Attempt) (cerberus.ValidationResult, error) {
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		if err := ctx.Err(); err != nil {
			lastErr = err
			break
		}

		raw, err := attempt(ctx)
		if err != nil {
			lastErr = fmt.Errorf("attempt %d/%d: %w", i+1, maxAttempts, err)
			continue
		}

		result, err := ParseValidationResult(raw)
		if err != nil {
			lastErr = fmt.Errorf("attempt %d/%d: %w", i+1, maxAttempts, err)
			continue
		}

		return result, nil
	}

	return FallbackResult(fmt.Sprintf(
		"llm validator degraded to uncertain after %d attempt(s): %v",
		maxAttempts, lastErr,
	)), lastErr
}
