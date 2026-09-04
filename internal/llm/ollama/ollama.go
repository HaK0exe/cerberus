package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/HaK0exe/cerberus/internal/llm"
	"github.com/HaK0exe/cerberus/internal/llm/prompt"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// Default configuration values, used for any zero-valued Config field
// passed to New.
const (
	// DefaultBaseURL is Ollama's standard local listen address. It is
	// only a default: Config.BaseURL always overrides it, so nothing in
	// this package hardcodes an unconfigurable endpoint.
	DefaultBaseURL = "http://localhost:11434"
	// DefaultTemplateID is the prompt template this package renders
	// against Prompts when Config.TemplateID is unset.
	DefaultTemplateID = "candidate_validation"
	// DefaultTimeout bounds a single call to Ollama's HTTP API.
	DefaultTimeout = 30 * time.Second
	// DefaultMaxAttempts is how many times a malformed/schema-violating
	// model response is retried before Validate degrades to
	// llm.FallbackResult, per internal/llm.ParseValidationResultWithRetry.
	DefaultMaxAttempts = 2

	// generatePath is Ollama's non-streaming single-turn generation
	// endpoint.
	generatePath = "/api/generate"

	// maxResponseBytes bounds how much of an HTTP response body this
	// package will read, so a misbehaving or malicious endpoint cannot
	// exhaust memory.
	maxResponseBytes = 1 << 20 // 1 MiB
)

// Sentinel errors Validate's returned error may wrap, so callers can
// tell an Ollama-side failure apart from a low-confidence
// classification with errors.Is — the FallbackResult Validate returns
// alongside such an error always reports
// cerberus.ClassificationUncertain at confidence 0, never a real model
// verdict, per docs/architecture/llm-non-sovereign.md.
var (
	// ErrConnectionFailed means the HTTP request to Ollama could not be
	// completed at all (connection refused, DNS failure, TLS error,
	// ...) — the Ollama runtime is not reachable at the configured
	// BaseURL.
	ErrConnectionFailed = errors.New("ollama: connection failed")

	// ErrModelNotFound means Ollama responded but reported that the
	// configured model is not pulled/available.
	ErrModelNotFound = errors.New("ollama: model not found")

	// ErrRequestFailed means Ollama responded with a non-success status
	// other than "model not found".
	ErrRequestFailed = errors.New("ollama: request failed")
)

// httpDoer is the subset of *http.Client this package depends on, so
// tests can inject a fake implementation (httptest server, or a stub
// returning canned errors) without a real Ollama instance listening
// anywhere. *http.Client satisfies this interface as-is.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config configures a Validator. BaseURL and Model are the only two
// values with an overridable default; every other Ollama endpoint
// detail is derived from them at call time, never hardcoded.
type Config struct {
	// BaseURL is the Ollama server's base URL, e.g.
	// "http://localhost:11434". Defaults to DefaultBaseURL if empty.
	BaseURL string

	// Model is the Ollama model name to request (e.g. "llama3.1:8b").
	// Required: New returns an error if this is empty, since there is no
	// safe default model to fall back to.
	Model string

	// Prompts is the loaded prompt template store Validate renders
	// requests against (see internal/llm/prompt.LoadDir). Required.
	Prompts *prompt.Store

	// TemplateID selects which template in Prompts to render. Defaults
	// to DefaultTemplateID.
	TemplateID string

	// Timeout bounds a single call to Ollama, applied fresh to every
	// retry attempt (see MaxAttempts). Defaults to DefaultTimeout. A
	// negative value disables the timeout, relying solely on the
	// caller's context.
	Timeout time.Duration

	// MaxAttempts is how many times Validate will retry after a
	// malformed or schema-violating model response before degrading to
	// llm.FallbackResult. Defaults to DefaultMaxAttempts.
	MaxAttempts int

	// HTTPClient is the HTTP transport used to reach Ollama. Defaults to
	// a plain &http.Client{}. Tests inject an httptest-backed client (or
	// any httpDoer) here.
	HTTPClient httpDoer
}

// Validator implements cerberus.Validator against a local Ollama
// instance. Build one with New. It holds no cache and no circuit
// breaker of its own — see internal/llm/cache and
// internal/llm/circuitbreaker, which wrap a Validator like this one
// rather than duplicating that behavior here.
type Validator struct {
	baseURL     string
	model       string
	prompts     *prompt.Store
	templateID  string
	timeout     time.Duration
	maxAttempts int
	httpClient  httpDoer
}

var _ cerberus.Validator = (*Validator)(nil)

// New builds a Validator from cfg, applying defaults to every unset
// field. It returns an error if a required field (Model, Prompts) is
// missing, or if the configured template cannot be found in Prompts.
func New(cfg Config) (*Validator, error) {
	if cfg.Model == "" {
		return nil, errors.New("ollama: Config.Model is required")
	}
	if cfg.Prompts == nil {
		return nil, errors.New("ollama: Config.Prompts is required")
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	templateID := cfg.TemplateID
	if templateID == "" {
		templateID = DefaultTemplateID
	}
	if _, err := cfg.Prompts.Get(templateID); err != nil {
		return nil, fmt.Errorf("ollama: resolving template %q: %w", templateID, err)
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < 0 {
		timeout = 0
	}

	maxAttempts := cfg.MaxAttempts
	if maxAttempts < 1 {
		maxAttempts = DefaultMaxAttempts
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	return &Validator{
		baseURL:     baseURL,
		model:       cfg.Model,
		prompts:     cfg.Prompts,
		templateID:  templateID,
		timeout:     timeout,
		maxAttempts: maxAttempts,
		httpClient:  httpClient,
	}, nil
}

// Validate implements cerberus.Validator. It sends only
// input.RedactedContext (rendered into the configured prompt template)
// to Ollama — never a raw secret value, per
// docs/architecture/llm-non-sovereign.md; callers are responsible for
// having already run the candidate context through llm.Sanitize before
// building input.
//
// The returned cerberus.ValidationResult is always safe to use, even
// when err is non-nil: a failed call degrades to llm.FallbackResult
// (cerberus.ClassificationUncertain, confidence 0), per
// internal/llm.ParseValidationResultWithRetry. err, when non-nil, wraps
// one of this package's sentinel errors (ErrConnectionFailed,
// ErrModelNotFound, ErrRequestFailed) or llm.ErrSchemaViolation so
// callers can distinguish an Ollama-side failure from a genuine
// low-confidence classification with errors.Is, rather than by
// inspecting Confidence.
func (v *Validator) Validate(ctx context.Context, input cerberus.ValidationInput) (cerberus.ValidationResult, error) {
	tmpl, err := v.prompts.Get(v.templateID)
	if err != nil {
		return llm.FallbackResult(fmt.Sprintf("ollama: resolving template %q: %v", v.templateID, err)),
			fmt.Errorf("ollama: resolving template %q: %w", v.templateID, err)
	}

	rendered, err := tmpl.Render(input)
	if err != nil {
		return llm.FallbackResult(fmt.Sprintf("ollama: rendering prompt: %v", err)),
			fmt.Errorf("ollama: rendering prompt: %w", err)
	}

	attempt := func(attemptCtx context.Context) ([]byte, error) {
		callCtx := attemptCtx
		if v.timeout > 0 {
			var cancel context.CancelFunc
			callCtx, cancel = context.WithTimeout(attemptCtx, v.timeout)
			defer cancel()
		}
		return v.generate(callCtx, rendered)
	}

	return llm.ParseValidationResultWithRetry(ctx, v.maxAttempts, attempt)
}

// ollamaGenerateRequest is the request body for Ollama's
// /api/generate endpoint in single-turn, non-streaming mode.
type ollamaGenerateRequest struct {
	Model   string         `json:"model"`
	Prompt  string         `json:"prompt"`
	Format  string         `json:"format,omitempty"`
	Stream  bool           `json:"stream"`
	Options map[string]any `json:"options,omitempty"`
}

// ollamaGenerateResponse is the subset of Ollama's /api/generate
// response envelope this package uses. Response holds the model's raw
// completion text, which is itself expected to be the JSON document
// internal/llm.ParseValidationResult validates — this package never
// parses that text itself.
type ollamaGenerateResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
	Error    string `json:"error"`
}

// generate performs one HTTP call to Ollama's generate endpoint and
// returns the model's raw completion text for
// internal/llm.ParseValidationResult to validate. It never logs or
// includes a response body in an error: the request body is derived
// from already-redacted context, but response bodies are not assumed
// safe to echo verbatim either.
func (v *Validator) generate(ctx context.Context, renderedPrompt string) ([]byte, error) {
	reqBody, err := json.Marshal(ollamaGenerateRequest{
		Model:  v.model,
		Prompt: renderedPrompt,
		Format: "json",
		Stream: false,
		Options: map[string]any{
			"temperature": 0,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("ollama: encoding request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, v.baseURL+generatePath, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("ollama: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := v.httpClient.Do(httpReq)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			// Caller-initiated cancellation or a per-call timeout: never
			// misreported as a connectivity failure so a caller can tell
			// "I gave up waiting" apart from "Ollama is unreachable".
			return nil, ctxErr
		}
		return nil, fmt.Errorf("%w: %s: %v", ErrConnectionFailed, v.baseURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("ollama: reading response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound || isModelNotFoundBody(body) {
		return nil, fmt.Errorf("%w: %q at %s", ErrModelNotFound, v.model, v.baseURL)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d from %s", ErrRequestFailed, resp.StatusCode, v.baseURL)
	}

	var parsed ollamaGenerateResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("ollama: decoding response envelope: %w", err)
	}
	if parsed.Error != "" {
		if isModelNotFoundBody(body) {
			return nil, fmt.Errorf("%w: %q at %s", ErrModelNotFound, v.model, v.baseURL)
		}
		return nil, fmt.Errorf("%w: ollama reported an error", ErrRequestFailed)
	}

	return []byte(parsed.Response), nil
}

// isModelNotFoundBody reports whether an Ollama error response body
// indicates the configured model is not available locally, so it can
// be surfaced as ErrModelNotFound regardless of the exact HTTP status
// a given Ollama version uses for that condition.
func isModelNotFoundBody(body []byte) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "not found") && strings.Contains(lower, "model")
}
