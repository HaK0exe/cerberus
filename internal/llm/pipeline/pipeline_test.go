package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/HaK0exe/cerberus/internal/llm/cache"
	"github.com/HaK0exe/cerberus/internal/llm/circuitbreaker"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

type stubValidator struct {
	result cerberus.ValidationResult
	err    error
	calls  int
}

func (s *stubValidator) Validate(ctx context.Context, in cerberus.ValidationInput) (cerberus.ValidationResult, error) {
	s.calls++
	return s.result, s.err
}

func newKeyDeriver(t *testing.T) *cache.KeyDeriver {
	t.Helper()
	d, err := cache.NewKeyDeriver([]byte("test-hmac-key-not-for-production"))
	if err != nil {
		t.Fatalf("NewKeyDeriver: %v", err)
	}
	return d
}

func TestNew_PrimarySuccessNeverCallsFallback(t *testing.T) {
	primary := &stubValidator{result: cerberus.ValidationResult{Classification: cerberus.ClassificationLikelySecret, Confidence: 0.8}}
	fallback := &stubValidator{result: cerberus.ValidationResult{Classification: cerberus.ClassificationUncertain}}

	v := New(Config{Primary: primary, Fallback: fallback})

	result, err := v.Validate(context.Background(), cerberus.ValidationInput{RuleID: "r1", Path: "p1"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Classification != cerberus.ClassificationLikelySecret {
		t.Errorf("expected primary's result, got %v", result.Classification)
	}
	if primary.calls != 1 {
		t.Errorf("expected primary to be called once, got %d", primary.calls)
	}
	if fallback.calls != 0 {
		t.Errorf("expected fallback to never be called when primary succeeds, got %d calls", fallback.calls)
	}
}

func TestNew_FallsBackToSecondaryWhenPrimaryFails(t *testing.T) {
	primary := &stubValidator{err: errors.New("connection refused")}
	fallback := &stubValidator{result: cerberus.ValidationResult{Classification: cerberus.ClassificationLikelyFalsePos, Confidence: 0.6}}

	v := New(Config{
		Primary:  primary,
		Fallback: fallback,
		Breaker:  circuitbreaker.Config{FailureThreshold: 100}, // never trip the breaker itself in this test
	})

	result, err := v.Validate(context.Background(), cerberus.ValidationInput{RuleID: "r1", Path: "p1"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Classification != cerberus.ClassificationLikelyFalsePos {
		t.Errorf("expected fallback's result once primary failed, got %v", result.Classification)
	}
	if primary.calls != 1 || fallback.calls != 1 {
		t.Errorf("expected exactly one call to each backend, got primary=%d fallback=%d", primary.calls, fallback.calls)
	}
}

func TestNew_AllBackendsFailingDegradesToFallbackResult(t *testing.T) {
	primary := &stubValidator{err: errors.New("boom")}
	fallback := &stubValidator{err: errors.New("boom too")}

	v := New(Config{
		Primary:  primary,
		Fallback: fallback,
		Breaker:  circuitbreaker.Config{FailureThreshold: 100},
	})

	result, err := v.Validate(context.Background(), cerberus.ValidationInput{RuleID: "r1", Path: "p1"})
	if err == nil {
		t.Fatal("expected a non-nil error when every backend fails")
	}
	if !circuitbreaker.IsFallback(err) {
		t.Errorf("expected the error to satisfy circuitbreaker.IsFallback, got %v", err)
	}
	if result.Classification != cerberus.ClassificationUncertain || result.Confidence != 0 {
		t.Errorf("expected a safe uncertain/0 fallback result, got %+v", result)
	}
}

func TestNew_CachingSkipsSecondCallForIdenticalCandidate(t *testing.T) {
	primary := &stubValidator{result: cerberus.ValidationResult{Classification: cerberus.ClassificationLikelySecret, Confidence: 0.85}}

	v := New(Config{
		Primary:         primary,
		Cache:           cache.NewMemCache(),
		CacheKey:        newKeyDeriver(t),
		CacheTTLSeconds: 60,
		ModelID:         "test-model",
		PromptVersion:   "v1",
		RulesVersion:    "v1",
	})

	in := cerberus.ValidationInput{RuleID: "r1", Path: "p1", RedactedContext: "ctx"}

	if _, err := v.Validate(context.Background(), in); err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	if _, err := v.Validate(context.Background(), in); err != nil {
		t.Fatalf("second Validate: %v", err)
	}
	if primary.calls != 1 {
		t.Errorf("expected the underlying backend to be called exactly once for an identical, repeated candidate, got %d calls", primary.calls)
	}
}

func TestNew_CachingDoesNotCollideOnDifferentCandidates(t *testing.T) {
	primary := &stubValidator{result: cerberus.ValidationResult{Classification: cerberus.ClassificationLikelySecret, Confidence: 0.85}}

	v := New(Config{
		Primary:         primary,
		Cache:           cache.NewMemCache(),
		CacheKey:        newKeyDeriver(t),
		CacheTTLSeconds: 60,
		ModelID:         "test-model",
		PromptVersion:   "v1",
		RulesVersion:    "v1",
	})

	if _, err := v.Validate(context.Background(), cerberus.ValidationInput{RuleID: "r1", Path: "p1", RedactedContext: "ctx-a"}); err != nil {
		t.Fatalf("Validate 1: %v", err)
	}
	if _, err := v.Validate(context.Background(), cerberus.ValidationInput{RuleID: "r2", Path: "p2", RedactedContext: "ctx-b"}); err != nil {
		t.Fatalf("Validate 2: %v", err)
	}
	if primary.calls != 2 {
		t.Errorf("expected two distinct candidates to both reach the backend, got %d calls", primary.calls)
	}
}

func TestNew_NoCacheConfiguredCallsBackendEveryTime(t *testing.T) {
	primary := &stubValidator{result: cerberus.ValidationResult{Classification: cerberus.ClassificationLikelySecret, Confidence: 0.85}}
	v := New(Config{Primary: primary})

	in := cerberus.ValidationInput{RuleID: "r1", Path: "p1"}
	_, _ = v.Validate(context.Background(), in)
	_, _ = v.Validate(context.Background(), in)

	if primary.calls != 2 {
		t.Errorf("expected no caching without Config.Cache configured, got %d calls", primary.calls)
	}
}

// slowValidator blocks past the configured breaker timeout, exercising
// the timeout path end-to-end through the composed pipeline.
type slowValidator struct{ delay time.Duration }

func (s slowValidator) Validate(ctx context.Context, in cerberus.ValidationInput) (cerberus.ValidationResult, error) {
	select {
	case <-time.After(s.delay):
		return cerberus.ValidationResult{Classification: cerberus.ClassificationLikelySecret, Confidence: 1}, nil
	case <-ctx.Done():
		return cerberus.ValidationResult{}, ctx.Err()
	}
}

func TestNew_TimeoutFallsBackWithoutBlocking(t *testing.T) {
	v := New(Config{
		Primary: slowValidator{delay: time.Second},
		Breaker: circuitbreaker.Config{CallTimeout: 10 * time.Millisecond},
	})

	start := time.Now()
	result, err := v.Validate(context.Background(), cerberus.ValidationInput{RuleID: "r1", Path: "p1"})
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("expected Validate to return promptly after the configured timeout, took %s", elapsed)
	}
	if !circuitbreaker.IsFallback(err) {
		t.Errorf("expected a fallback error after a timeout, got %v", err)
	}
	if result.Classification != cerberus.ClassificationUncertain {
		t.Errorf("expected a safe fallback result after a timeout, got %+v", result)
	}
}
