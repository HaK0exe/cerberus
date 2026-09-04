package circuitbreaker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// fakeValidator is a controllable cerberus.Validator test double.
type fakeValidator struct {
	mu sync.Mutex

	// fn, if set, is called for every Validate invocation.
	fn func(ctx context.Context, input cerberus.ValidationInput) (cerberus.ValidationResult, error)

	calls int32
}

func (f *fakeValidator) Validate(ctx context.Context, input cerberus.ValidationInput) (cerberus.ValidationResult, error) {
	atomic.AddInt32(&f.calls, 1)
	f.mu.Lock()
	fn := f.fn
	f.mu.Unlock()
	return fn(ctx, input)
}

func (f *fakeValidator) callCount() int32 { return atomic.LoadInt32(&f.calls) }

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func okResult() cerberus.ValidationResult {
	return cerberus.ValidationResult{Classification: cerberus.ClassificationLikelySecret, Confidence: 0.9}
}

// --- timeout ---------------------------------------------------------

func TestValidate_TimeoutFallsBack(t *testing.T) {
	fv := &fakeValidator{fn: func(ctx context.Context, _ cerberus.ValidationInput) (cerberus.ValidationResult, error) {
		<-ctx.Done() // respects cancellation, but "hangs" until the caller times out
		return cerberus.ValidationResult{}, ctx.Err()
	}}

	b := New(fv, Config{
		CallTimeout:      20 * time.Millisecond,
		FailureThreshold: 100, // don't let the breaker open in this test
		Logger:           silentLogger(),
	})

	start := time.Now()
	result, err := b.Validate(context.Background(), cerberus.ValidationInput{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error for a hung validator call")
	}
	if !IsFallback(err) {
		t.Fatalf("expected IsFallback(err) to be true, got %v", err)
	}
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected error to wrap ErrTimeout, got %v", err)
	}
	if result != (cerberus.ValidationResult{}) {
		t.Fatalf("expected zero-value result on fallback, got %+v", result)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Validate did not return promptly after timeout: took %v", elapsed)
	}
}

// --- circuit opens after N consecutive failures -----------------------

func TestValidate_OpensAfterConsecutiveFailures(t *testing.T) {
	wantErr := errors.New("model exploded")
	fv := &fakeValidator{fn: func(_ context.Context, _ cerberus.ValidationInput) (cerberus.ValidationResult, error) {
		return cerberus.ValidationResult{}, wantErr
	}}

	b := New(fv, Config{
		CallTimeout:      time.Second,
		FailureThreshold: 3,
		OpenDuration:     time.Hour, // won't elapse during this test
		Logger:           silentLogger(),
	})

	for i := 0; i < 3; i++ {
		_, err := b.Validate(context.Background(), cerberus.ValidationInput{})
		if !IsFallback(err) {
			t.Fatalf("call %d: expected fallback error, got %v", i, err)
		}
	}

	if got := b.State(); got != StateOpen {
		t.Fatalf("expected breaker to be open after %d consecutive failures, got %v", 3, got)
	}

	// One more call: must NOT reach the underlying validator.
	callsBefore := fv.callCount()
	_, err := b.Validate(context.Background(), cerberus.ValidationInput{})
	if !IsFallback(err) {
		t.Fatalf("expected fallback error while open, got %v", err)
	}
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected error to wrap ErrCircuitOpen, got %v", err)
	}
	if fv.callCount() != callsBefore {
		t.Fatalf("expected underlying validator not to be called while breaker is open, calls went from %d to %d", callsBefore, fv.callCount())
	}
}

// --- half-open: success closes the breaker -----------------------------

func TestValidate_HalfOpenProbeSucceedsCloses(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)

	fv := &fakeValidator{fn: func(_ context.Context, _ cerberus.ValidationInput) (cerberus.ValidationResult, error) {
		if failing.Load() {
			return cerberus.ValidationResult{}, errors.New("boom")
		}
		return okResult(), nil
	}}

	now := time.Now()
	clock := func() time.Time { return now }

	b := New(fv, Config{
		CallTimeout:      time.Second,
		FailureThreshold: 2,
		OpenDuration:     10 * time.Second,
		Now:              clock,
		Logger:           silentLogger(),
	})

	for i := 0; i < 2; i++ {
		if _, err := b.Validate(context.Background(), cerberus.ValidationInput{}); !IsFallback(err) {
			t.Fatalf("expected fallback on failure %d, got %v", i, err)
		}
	}
	if b.State() != StateOpen {
		t.Fatalf("expected open state, got %v", b.State())
	}

	// Advance the fake clock past OpenDuration and let the model "recover".
	now = now.Add(11 * time.Second)
	failing.Store(false)

	result, err := b.Validate(context.Background(), cerberus.ValidationInput{})
	if err != nil {
		t.Fatalf("expected successful probe call, got error %v", err)
	}
	if result != okResult() {
		t.Fatalf("expected real result from probe, got %+v", result)
	}
	if b.State() != StateClosed {
		t.Fatalf("expected breaker to close after successful probe, got %v", b.State())
	}

	// Breaker is closed again: subsequent calls should reach the validator.
	callsBefore := fv.callCount()
	if _, err := b.Validate(context.Background(), cerberus.ValidationInput{}); err != nil {
		t.Fatalf("unexpected error after close: %v", err)
	}
	if fv.callCount() != callsBefore+1 {
		t.Fatal("expected the underlying validator to be called again once closed")
	}
}

// --- half-open: failure reopens immediately -----------------------------

func TestValidate_HalfOpenProbeFailsReopens(t *testing.T) {
	fv := &fakeValidator{fn: func(_ context.Context, _ cerberus.ValidationInput) (cerberus.ValidationResult, error) {
		return cerberus.ValidationResult{}, errors.New("still broken")
	}}

	now := time.Now()
	clock := func() time.Time { return now }

	b := New(fv, Config{
		CallTimeout:      time.Second,
		FailureThreshold: 1,
		OpenDuration:     time.Second,
		Now:              clock,
		Logger:           silentLogger(),
	})

	if _, err := b.Validate(context.Background(), cerberus.ValidationInput{}); !IsFallback(err) {
		t.Fatalf("expected fallback, got %v", err)
	}
	if b.State() != StateOpen {
		t.Fatalf("expected open, got %v", b.State())
	}

	now = now.Add(2 * time.Second)

	// The probe call itself fails too -> breaker must go straight back to open.
	if _, err := b.Validate(context.Background(), cerberus.ValidationInput{}); !IsFallback(err) {
		t.Fatalf("expected fallback for failed probe, got %v", err)
	}
	if b.State() != StateOpen {
		t.Fatalf("expected breaker to reopen after failed probe, got %v", b.State())
	}

	// Immediately retrying (before OpenDuration elapses again) must short-circuit.
	callsBefore := fv.callCount()
	if _, err := b.Validate(context.Background(), cerberus.ValidationInput{}); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen, got %v", err)
	}
	if fv.callCount() != callsBefore {
		t.Fatal("expected no underlying call while freshly reopened")
	}
}

// --- caller cancellation is not a breaker failure -----------------------

func TestValidate_CallerCancellationNotCountedAsFailure(t *testing.T) {
	fv := &fakeValidator{fn: func(ctx context.Context, _ cerberus.ValidationInput) (cerberus.ValidationResult, error) {
		<-ctx.Done()
		return cerberus.ValidationResult{}, ctx.Err()
	}}

	b := New(fv, Config{
		CallTimeout:      time.Minute, // long enough that only caller cancellation fires
		FailureThreshold: 1,
		Logger:           silentLogger(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	_, err := b.Validate(ctx, cerberus.ValidationInput{})
	if err == nil {
		t.Fatal("expected an error from a canceled context")
	}
	if IsFallback(err) {
		t.Fatalf("caller cancellation must not be reported as a fallback, got %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if b.State() != StateClosed {
		t.Fatalf("caller cancellation must not open the breaker, got %v", b.State())
	}
}

// --- success passes the real result through, untouched -----------------

func TestValidate_SuccessPassesThrough(t *testing.T) {
	fv := &fakeValidator{fn: func(_ context.Context, _ cerberus.ValidationInput) (cerberus.ValidationResult, error) {
		return okResult(), nil
	}}
	b := New(fv, Config{Logger: silentLogger()})

	result, err := b.Validate(context.Background(), cerberus.ValidationInput{RuleID: "aws-access-key-id"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != okResult() {
		t.Fatalf("expected pass-through result, got %+v", result)
	}
	if b.State() != StateClosed {
		t.Fatalf("expected closed state after success, got %v", b.State())
	}
}

// --- no goroutine leak --------------------------------------------------

func TestValidate_NoGoroutineLeak(t *testing.T) {
	fv := &fakeValidator{fn: func(ctx context.Context, _ cerberus.ValidationInput) (cerberus.ValidationResult, error) {
		<-ctx.Done()
		return cerberus.ValidationResult{}, ctx.Err()
	}}

	b := New(fv, Config{
		CallTimeout:      5 * time.Millisecond,
		FailureThreshold: 1000,
		Logger:           silentLogger(),
	})

	before := runtime.NumGoroutine()

	for i := 0; i < 50; i++ {
		_, _ = b.Validate(context.Background(), cerberus.ValidationInput{})
	}

	// Give the underlying goroutines a moment to observe cancellation and
	// exit after writing to their buffered channel.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	after := runtime.NumGoroutine()
	if after > before+2 {
		t.Fatalf("possible goroutine leak: before=%d after=%d", before, after)
	}
}

// --- Stats reflects call/failure/open counters --------------------------

func TestStats(t *testing.T) {
	fv := &fakeValidator{fn: func(_ context.Context, _ cerberus.ValidationInput) (cerberus.ValidationResult, error) {
		return cerberus.ValidationResult{}, errors.New("boom")
	}}
	b := New(fv, Config{FailureThreshold: 2, OpenDuration: time.Hour, Logger: silentLogger()})

	for i := 0; i < 3; i++ {
		_, _ = b.Validate(context.Background(), cerberus.ValidationInput{})
	}

	stats := b.Stats()
	if stats.State != StateOpen {
		t.Fatalf("expected open state, got %v", stats.State)
	}
	if stats.TotalCalls != 3 {
		t.Fatalf("expected 3 total calls, got %d", stats.TotalCalls)
	}
	if stats.TotalFailures != 2 {
		t.Fatalf("expected 2 recorded failures (3rd is short-circuited), got %d", stats.TotalFailures)
	}
	if stats.TotalOpens != 1 {
		t.Fatalf("expected 1 open transition, got %d", stats.TotalOpens)
	}
	if stats.TotalFallbacks != 1 {
		t.Fatalf("expected 1 short-circuited fallback, got %d", stats.TotalFallbacks)
	}
}

// --- New panics on nil validator -----------------------------------------

func TestNew_PanicsOnNilValidator(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected New(nil, ...) to panic")
		}
	}()
	New(nil, Config{})
}

var _ cerberus.Validator = (*Breaker)(nil)
