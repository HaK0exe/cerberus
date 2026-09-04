package llm_test

import (
	"context"
	"errors"
	"testing"

	"github.com/HaK0exe/cerberus/internal/llm"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func TestParseValidationResult_Valid(t *testing.T) {
	raw := []byte(`{"classification":"likely_secret","confidence":0.87,"reason":"looks like a live AWS key"}`)

	got, err := llm.ParseValidationResult(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := cerberus.ValidationResult{
		Classification: cerberus.ClassificationLikelySecret,
		Confidence:     0.87,
		Reason:         "looks like a live AWS key",
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseValidationResult_ValidAllClassifications(t *testing.T) {
	cases := []cerberus.ValidationClassification{
		cerberus.ClassificationLikelySecret,
		cerberus.ClassificationLikelyFalsePos,
		cerberus.ClassificationUncertain,
	}
	for _, c := range cases {
		raw := []byte(`{"classification":"` + string(c) + `","confidence":0.5,"reason":"x"}`)
		got, err := llm.ParseValidationResult(raw)
		if err != nil {
			t.Fatalf("classification %q: unexpected error: %v", c, err)
		}
		if got.Classification != c {
			t.Fatalf("classification %q: got %q", c, got.Classification)
		}
	}
}

func TestParseValidationResult_EmptyResponse(t *testing.T) {
	_, err := llm.ParseValidationResult(nil)
	assertSchemaViolation(t, err)

	_, err = llm.ParseValidationResult([]byte("   "))
	assertSchemaViolation(t, err)
}

func TestParseValidationResult_MalformedJSON(t *testing.T) {
	raw := []byte(`{"classification": "likely_secret", "confidence": 0.5, "reason": "unterminated`)
	_, err := llm.ParseValidationResult(raw)
	assertSchemaViolation(t, err)
}

func TestParseValidationResult_NotAnObject(t *testing.T) {
	raw := []byte(`"just a string"`)
	_, err := llm.ParseValidationResult(raw)
	assertSchemaViolation(t, err)
}

func TestParseValidationResult_TrailingData(t *testing.T) {
	raw := []byte(`{"classification":"likely_secret","confidence":0.5,"reason":"ok"} {"classification":"uncertain","confidence":0,"reason":"extra"}`)
	_, err := llm.ParseValidationResult(raw)
	assertSchemaViolation(t, err)
}

func TestParseValidationResult_MissingFields(t *testing.T) {
	cases := map[string][]byte{
		"missing classification": []byte(`{"confidence":0.5,"reason":"ok"}`),
		"missing confidence":     []byte(`{"classification":"likely_secret","reason":"ok"}`),
		"missing reason":         []byte(`{"classification":"likely_secret","confidence":0.5}`),
		"empty object":           []byte(`{}`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := llm.ParseValidationResult(raw)
			assertSchemaViolation(t, err)
		})
	}
}

func TestParseValidationResult_UnknownField(t *testing.T) {
	raw := []byte(`{"classification":"likely_secret","confidence":0.5,"reason":"ok","extra":"field"}`)
	_, err := llm.ParseValidationResult(raw)
	assertSchemaViolation(t, err)
}

func TestParseValidationResult_InvalidClassification(t *testing.T) {
	raw := []byte(`{"classification":"definitely_a_secret","confidence":0.5,"reason":"ok"}`)
	_, err := llm.ParseValidationResult(raw)
	assertSchemaViolation(t, err)
}

func TestParseValidationResult_ConfidenceWrongType(t *testing.T) {
	raw := []byte(`{"classification":"likely_secret","confidence":"high","reason":"ok"}`)
	_, err := llm.ParseValidationResult(raw)
	assertSchemaViolation(t, err)
}

func TestParseValidationResult_ConfidenceClamped(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want float64
	}{
		{"above one", `{"classification":"likely_secret","confidence":1.5,"reason":"ok"}`, 1},
		{"below zero", `{"classification":"likely_secret","confidence":-0.3,"reason":"ok"}`, 0},
		{"exactly zero", `{"classification":"uncertain","confidence":0,"reason":"ok"}`, 0},
		{"exactly one", `{"classification":"likely_secret","confidence":1,"reason":"ok"}`, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := llm.ParseValidationResult([]byte(tc.raw))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Confidence != tc.want {
				t.Fatalf("confidence = %v, want %v", got.Confidence, tc.want)
			}
		})
	}
}

func TestParseValidationResult_ConfidenceNonFinite(t *testing.T) {
	// A huge decimal exponent is valid JSON but overflows float64 to
	// +Inf, which must be rejected as a schema violation rather than
	// silently clamped.
	raw := []byte(`{"classification":"likely_secret","confidence":1e400,"reason":"ok"}`)
	_, err := llm.ParseValidationResult(raw)
	assertSchemaViolation(t, err)
}

func TestParseValidationResult_ZeroValueOnError(t *testing.T) {
	got, err := llm.ParseValidationResult([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error")
	}
	if got != (cerberus.ValidationResult{}) {
		t.Fatalf("expected zero-value result on error, got %+v", got)
	}
}

func assertSchemaViolation(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, llm.ErrSchemaViolation) {
		t.Fatalf("expected error to wrap ErrSchemaViolation, got: %v", err)
	}
}

func TestParseValidationResultWithRetry_SucceedsFirstTry(t *testing.T) {
	calls := 0
	attempt := func(ctx context.Context) ([]byte, error) {
		calls++
		return []byte(`{"classification":"likely_secret","confidence":0.9,"reason":"ok"}`), nil
	}

	got, err := llm.ParseValidationResultWithRetry(context.Background(), 3, attempt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
	if got.Classification != cerberus.ClassificationLikelySecret {
		t.Fatalf("unexpected classification: %+v", got)
	}
}

func TestParseValidationResultWithRetry_RecoversAfterMalformedAttempt(t *testing.T) {
	calls := 0
	attempt := func(ctx context.Context) ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte(`not json at all`), nil
		}
		return []byte(`{"classification":"uncertain","confidence":0.4,"reason":"retried ok"}`), nil
	}

	got, err := llm.ParseValidationResultWithRetry(context.Background(), 3, attempt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}
	if got.Reason != "retried ok" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestParseValidationResultWithRetry_ExhaustedDegradesToUncertain(t *testing.T) {
	calls := 0
	attempt := func(ctx context.Context) ([]byte, error) {
		calls++
		return []byte(`still not json`), nil
	}

	got, err := llm.ParseValidationResultWithRetry(context.Background(), 3, attempt)
	if err == nil {
		t.Fatal("expected error describing the exhausted retries")
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
	if got.Classification != cerberus.ClassificationUncertain || got.Confidence != 0 {
		t.Fatalf("expected safe uncertain fallback, got %+v", got)
	}
}

func TestParseValidationResultWithRetry_AttemptTransportError(t *testing.T) {
	calls := 0
	wantErr := errors.New("model runtime unreachable")
	attempt := func(ctx context.Context) ([]byte, error) {
		calls++
		return nil, wantErr
	}

	got, err := llm.ParseValidationResultWithRetry(context.Background(), 2, attempt)
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}
	if got.Classification != cerberus.ClassificationUncertain {
		t.Fatalf("expected safe uncertain fallback, got %+v", got)
	}
}

func TestParseValidationResultWithRetry_ZeroOrNegativeMaxAttemptsTreatedAsOne(t *testing.T) {
	calls := 0
	attempt := func(ctx context.Context) ([]byte, error) {
		calls++
		return []byte(`{"classification":"likely_secret","confidence":0.5,"reason":"ok"}`), nil
	}

	got, err := llm.ParseValidationResultWithRetry(context.Background(), 0, attempt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
	if got.Classification != cerberus.ClassificationLikelySecret {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestParseValidationResultWithRetry_ContextCanceledStopsRetrying(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := 0
	attempt := func(ctx context.Context) ([]byte, error) {
		calls++
		return []byte(`not json`), nil
	}

	got, err := llm.ParseValidationResultWithRetry(ctx, 5, attempt)
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 0 {
		t.Fatalf("expected attempt to never run once the context is already canceled, got %d calls", calls)
	}
	if got.Classification != cerberus.ClassificationUncertain {
		t.Fatalf("expected safe uncertain fallback, got %+v", got)
	}
}
