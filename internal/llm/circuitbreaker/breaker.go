// Package circuitbreaker wraps a cerberus.Validator with a per-call
// timeout and a circuit breaker so that a hung or repeatedly-failing
// local LLM (Ollama, llama.cpp, ...) can never stall or block a scan.
//
// The LLM validation stage is optional and non-authoritative (see
// docs/architecture/llm-non-sovereign.md): if the underlying Validator
// times out, errors, or the breaker is open, Breaker.Validate returns a
// zero-value cerberus.ValidationResult together with an error that
// wraps ErrFallback. Callers should treat any error satisfying
// errors.Is(err, ErrFallback) as "run the candidate as if the LLM
// stage did not exist" (i.e. keep the pre-LLM deterministic score)
// rather than as a blocking failure — see IsFallback.
//
// Caller-initiated cancellation of the context passed to Validate is
// never treated as a breaker failure: it is returned unwrapped so the
// caller can distinguish "I gave up waiting" from "the model failed".
package circuitbreaker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// State is a circuit breaker state.
type State int32

const (
	// StateClosed is the normal operating state: calls are forwarded to
	// the underlying Validator.
	StateClosed State = iota
	// StateOpen means the breaker has tripped: calls are short-circuited
	// straight to the fallback without touching the underlying Validator.
	StateOpen
	// StateHalfOpen means the recovery period has elapsed and a bounded
	// number of trial calls are being let through to probe whether the
	// underlying Validator has recovered.
	StateHalfOpen
)

// String implements fmt.Stringer for logging/metrics.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// Default tuning values, used for any zero-valued Config field passed
// to New.
const (
	DefaultCallTimeout      = 5 * time.Second
	DefaultFailureThreshold = 5
	DefaultOpenDuration     = 30 * time.Second
	DefaultHalfOpenMaxCalls = 1
)

// Sentinel errors returned by Breaker.Validate.
var (
	// ErrFallback is wrapped into every error Validate returns when the
	// caller should fall back to the pre-LLM deterministic score instead
	// of treating the error as blocking. Check with errors.Is or
	// IsFallback.
	ErrFallback = errors.New("llm validator unavailable: falling back to deterministic score")

	// ErrCircuitOpen means the breaker short-circuited the call without
	// invoking the underlying Validator.
	ErrCircuitOpen = errors.New("circuit breaker open")

	// ErrTimeout means the underlying Validator did not return within
	// the configured CallTimeout.
	ErrTimeout = errors.New("llm validator call timed out")
)

// IsFallback reports whether err (from Breaker.Validate) signals that
// the caller should proceed as if the LLM stage did not exist, i.e.
// keep the pre-LLM deterministic score. It is equivalent to
// errors.Is(err, ErrFallback).
func IsFallback(err error) bool {
	return errors.Is(err, ErrFallback)
}

// Config tunes a Breaker. All fields are optional; zero values fall
// back to the Default* constants.
type Config struct {
	// CallTimeout bounds every individual call to the underlying
	// Validator. Defaults to DefaultCallTimeout.
	CallTimeout time.Duration

	// FailureThreshold is the number of consecutive failures (timeouts
	// or errors) required to open the breaker. Defaults to
	// DefaultFailureThreshold.
	FailureThreshold int

	// OpenDuration is how long the breaker stays open before allowing a
	// half-open probe call through. Defaults to DefaultOpenDuration.
	OpenDuration time.Duration

	// HalfOpenMaxCalls is the number of concurrent trial calls allowed
	// through while half-open. Defaults to DefaultHalfOpenMaxCalls.
	HalfOpenMaxCalls int

	// Logger receives structured state-transition and fallback events.
	// Defaults to slog.Default().
	Logger *slog.Logger

	// Now returns the current time. Overridable for tests. Defaults to
	// time.Now.
	Now func() time.Time

	// OnStateChange, if set, is invoked (outside the breaker's lock)
	// whenever the breaker transitions from one state to another. Useful
	// for wiring in a metrics counter/gauge.
	OnStateChange func(from, to State)
}

func (c Config) withDefaults() Config {
	if c.CallTimeout <= 0 {
		c.CallTimeout = DefaultCallTimeout
	}
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = DefaultFailureThreshold
	}
	if c.OpenDuration <= 0 {
		c.OpenDuration = DefaultOpenDuration
	}
	if c.HalfOpenMaxCalls <= 0 {
		c.HalfOpenMaxCalls = DefaultHalfOpenMaxCalls
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// Stats is a point-in-time, read-only snapshot of a Breaker's state,
// suitable for exposing on a metrics/status endpoint.
type Stats struct {
	State               State
	ConsecutiveFailures int
	TotalCalls          uint64
	TotalFailures       uint64
	TotalFallbacks      uint64
	TotalOpens          uint64
	OpenedAt            time.Time
}

// Breaker wraps a cerberus.Validator with a per-call timeout and a
// circuit breaker. Breaker itself implements cerberus.Validator, so it
// is a drop-in decorator around any Validator implementation
// (Ollama, llama.cpp, a test double, ...).
type Breaker struct {
	validator cerberus.Validator
	cfg       Config

	mu                  sync.Mutex
	state               State
	consecutiveFailures int
	openedAt            time.Time
	halfOpenInFlight    int
	stats               Stats
}

// New wraps validator with the given Config. validator must not be
// nil.
func New(validator cerberus.Validator, cfg Config) *Breaker {
	if validator == nil {
		panic("circuitbreaker: validator must not be nil")
	}
	return &Breaker{
		validator: validator,
		cfg:       cfg.withDefaults(),
		state:     StateClosed,
	}
}

// State returns the breaker's current state.
func (b *Breaker) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// Stats returns a snapshot of the breaker's counters, for logging or a
// metrics exporter.
func (b *Breaker) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.stats
	s.State = b.state
	s.ConsecutiveFailures = b.consecutiveFailures
	s.OpenedAt = b.openedAt
	return s
}

// admission records what the breaker decided when a call was let
// through, so the matching record{Success,Failure} call knows whether
// it was a half-open probe.
type admission struct {
	wasHalfOpenProbe bool
}

// Validate implements cerberus.Validator. It never blocks longer than
// Config.CallTimeout, and it never returns a "hard" error for a
// breaker-open or timeout condition: those come back wrapped in
// ErrFallback so the caller can safely treat the candidate as if the
// LLM stage did not run. A context canceled/deadline-exceeded by the
// caller is returned unwrapped and is not counted as a breaker
// failure.
func (b *Breaker) Validate(ctx context.Context, input cerberus.ValidationInput) (cerberus.ValidationResult, error) {
	adm, admitted, err := b.admit()
	if !admitted {
		return cerberus.ValidationResult{}, err
	}

	result, callErr := b.callWithTimeout(ctx, input)
	if callErr != nil {
		if parentErr := ctx.Err(); parentErr != nil && errors.Is(callErr, parentErr) {
			// The caller gave up (its own ctx was canceled/expired), not
			// the model. Don't penalize the breaker; return unwrapped so
			// the caller sees its own cancellation, not a fallback.
			b.release(adm)
			return cerberus.ValidationResult{}, callErr
		}
		b.recordFailure(adm)
		return cerberus.ValidationResult{}, fmt.Errorf("%w: %w", ErrFallback, callErr)
	}

	b.recordSuccess(adm)
	return result, nil
}

// callWithTimeout runs the underlying Validator bounded by
// Config.CallTimeout. The underlying call runs in its own goroutine
// writing to a buffered channel, so a Validator implementation that
// ignores context cancellation and keeps running after the timeout
// fires still cannot block Validate itself or leak: the goroutine
// exits as soon as the (non-blocking) send completes, once the
// underlying call eventually returns.
func (b *Breaker) callWithTimeout(ctx context.Context, input cerberus.ValidationInput) (cerberus.ValidationResult, error) {
	cctx, cancel := context.WithTimeout(ctx, b.cfg.CallTimeout)
	defer cancel()

	type outcome struct {
		result cerberus.ValidationResult
		err    error
	}
	ch := make(chan outcome, 1)
	go func() {
		r, err := b.validator.Validate(cctx, input)
		ch <- outcome{r, err}
	}()

	select {
	case out := <-ch:
		return out.result, out.err
	case <-cctx.Done():
		if parentErr := ctx.Err(); parentErr != nil {
			return cerberus.ValidationResult{}, parentErr
		}
		return cerberus.ValidationResult{}, ErrTimeout
	}
}

// admit decides whether a call should be forwarded to the underlying
// Validator given the current breaker state, transitioning
// Open->HalfOpen when the recovery period has elapsed.
func (b *Breaker) admit() (admission, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.stats.TotalCalls++

	switch b.state {
	case StateOpen:
		if b.cfg.Now().Sub(b.openedAt) >= b.cfg.OpenDuration {
			b.setState(StateHalfOpen, "recovery period elapsed, probing")
			b.halfOpenInFlight = 1
			return admission{wasHalfOpenProbe: true}, true, nil
		}
		b.stats.TotalFallbacks++
		b.cfg.Logger.Debug("circuit breaker open, falling back to deterministic score",
			"component", "llm.circuitbreaker", "state", b.state.String())
		return admission{}, false, fmt.Errorf("%w: %w", ErrFallback, ErrCircuitOpen)

	case StateHalfOpen:
		if b.halfOpenInFlight >= b.cfg.HalfOpenMaxCalls {
			b.stats.TotalFallbacks++
			return admission{}, false, fmt.Errorf("%w: %w", ErrFallback, ErrCircuitOpen)
		}
		b.halfOpenInFlight++
		return admission{wasHalfOpenProbe: true}, true, nil

	default: // StateClosed
		return admission{}, true, nil
	}
}

// release returns an admitted-but-uncounted call's half-open slot
// without affecting failure/success counters (used for caller-side
// cancellations, which are neither a success nor a Validator
// failure).
func (b *Breaker) release(adm admission) {
	if !adm.wasHalfOpenProbe {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.halfOpenInFlight > 0 {
		b.halfOpenInFlight--
	}
}

func (b *Breaker) recordSuccess(adm admission) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.consecutiveFailures = 0
	if adm.wasHalfOpenProbe && b.halfOpenInFlight > 0 {
		b.halfOpenInFlight--
	}
	if b.state != StateClosed {
		b.setState(StateClosed, "probe succeeded")
	}
}

func (b *Breaker) recordFailure(adm admission) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.stats.TotalFailures++

	if b.state == StateHalfOpen {
		if b.halfOpenInFlight > 0 {
			b.halfOpenInFlight--
		}
		b.openedAt = b.cfg.Now()
		b.stats.TotalOpens++
		b.setState(StateOpen, "probe failed")
		return
	}

	b.consecutiveFailures++
	if b.consecutiveFailures >= b.cfg.FailureThreshold {
		b.openedAt = b.cfg.Now()
		b.stats.TotalOpens++
		b.setState(StateOpen, "consecutive failure threshold reached")
	}
}

// setState must be called with b.mu held. It updates b.state, logs the
// transition, and (outside the lock is not required here since
// OnStateChange is expected to be cheap/non-reentrant, but we avoid
// calling back into the breaker) invokes the OnStateChange hook.
func (b *Breaker) setState(to State, reason string) {
	from := b.state
	if from == to {
		return
	}
	b.state = to

	level := slog.LevelInfo
	if to == StateOpen {
		level = slog.LevelWarn
	}
	b.cfg.Logger.Log(context.Background(), level,
		"llm circuit breaker state change",
		"component", "llm.circuitbreaker",
		"from", from.String(),
		"to", to.String(),
		"reason", reason,
		"consecutive_failures", b.consecutiveFailures,
	)

	if b.cfg.OnStateChange != nil {
		b.cfg.OnStateChange(from, to)
	}
}
