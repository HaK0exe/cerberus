package llamacpp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/HaK0exe/cerberus/internal/llm"
	"github.com/HaK0exe/cerberus/internal/llm/prompt"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

var _ cerberus.Validator = (*Validator)(nil)

// defaultPromptTemplateID is the prompt.Store template used to render a
// ValidationInput when Config.PromptTemplateID is left empty. See
// prompts/candidate_validation.md.
const defaultPromptTemplateID = "candidate_validation"

// defaultChatCompletionsPath is the OpenAI-compatible chat completions
// endpoint llama.cpp's built-in HTTP server exposes
// (https://github.com/ggml-org/llama.cpp/tree/master/tools/server).
const defaultChatCompletionsPath = "/v1/chat/completions"

// defaultMaxAttempts bounds how many times Validate will call the
// server for a single Validate call when the response fails schema
// validation, per internal/llm.ParseValidationResultWithRetry's
// documented retry/degrade policy.
const defaultMaxAttempts = 2

// HTTPClient is the subset of *http.Client the Validator depends on.
// Tests inject a fake implementation (httptest.Server-backed or an
// in-process stub) instead of talking to a real llama.cpp server.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config configures a Validator. BaseURL and Model are required and
// deliberately not defaulted to a hardcoded value: which llama.cpp
// server/model to use is a deployment decision, never baked into the
// binary.
type Config struct {
	// BaseURL is the llama.cpp server's base URL, e.g.
	// "http://localhost:8080". No path suffix.
	BaseURL string
	// Model is the model name/path the server should route the request
	// to. llama.cpp's server accepts (and, for a single-model server,
	// generally ignores) this field, but it is required here so calls
	// against a multi-model server (or an OpenAI-compatible proxy in
	// front of one) are unambiguous and reproducible.
	Model string
	// PromptTemplateID selects the internal/llm/prompt.Store template
	// used to render a cerberus.ValidationInput. Defaults to
	// "candidate_validation" (prompts/candidate_validation.md) when
	// empty.
	PromptTemplateID string
	// MaxAttempts bounds how many times a single Validate call may hit
	// the server before degrading to llm.FallbackResult, per
	// llm.ParseValidationResultWithRetry. Defaults to 2 when <= 0.
	MaxAttempts int
	// Temperature is passed through to the server's sampling params. A
	// low value (0 is the zero-value default, and llama.cpp treats an
	// absent/zero temperature as its own default) is recommended for
	// a classification task where determinism matters more than
	// variety.
	Temperature float64
	// HTTPClient performs the actual HTTP round trip. Defaults to
	// http.DefaultClient when nil.
	HTTPClient HTTPClient
}

// Validator implements cerberus.Validator against a llama.cpp server's
// OpenAI-compatible /v1/chat/completions endpoint.
type Validator struct {
	baseURL          string
	model            string
	promptTemplateID string
	maxAttempts      int
	temperature      float64
	httpClient       HTTPClient
	prompts          *prompt.Store
}

// New constructs a Validator. store must have the template named by
// cfg.PromptTemplateID (or "candidate_validation" if left empty)
// loaded — see prompt.LoadDir. Returns an error if cfg.BaseURL,
// cfg.Model, or store is unset, so a misconfigured Validator fails at
// construction time rather than on the first Validate call.
func New(cfg Config, store *prompt.Store) (*Validator, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("llamacpp: Config.BaseURL is required")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, errors.New("llamacpp: Config.Model is required")
	}
	if store == nil {
		return nil, errors.New("llamacpp: prompt.Store is required")
	}

	templateID := cfg.PromptTemplateID
	if templateID == "" {
		templateID = defaultPromptTemplateID
	}
	if _, err := store.Get(templateID); err != nil {
		return nil, fmt.Errorf("llamacpp: prompt template %q not loaded in store: %w", templateID, err)
	}

	maxAttempts := cfg.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = defaultMaxAttempts
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &Validator{
		baseURL:          strings.TrimRight(cfg.BaseURL, "/"),
		model:            cfg.Model,
		promptTemplateID: templateID,
		maxAttempts:      maxAttempts,
		temperature:      cfg.Temperature,
		httpClient:       httpClient,
		prompts:          store,
	}, nil
}

// chatMessage mirrors the OpenAI-compatible chat message shape.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatCompletionRequest mirrors the OpenAI-compatible
// /v1/chat/completions request body that llama.cpp's server accepts.
type chatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	Stream      bool          `json:"stream"`
}

// chatCompletionResponse mirrors the subset of the OpenAI-compatible
// response this adapter reads. Anything else in the body is ignored.
type chatCompletionResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Validate renders input through the configured prompt template, sends
// it to the llama.cpp server, and parses the response into a
// cerberus.ValidationResult via internal/llm.ParseValidationResultWithRetry.
// It never returns a raw secret value or logs the server's response
// body verbatim in an error beyond what is necessary to describe a
// transport/parse failure — input.RedactedContext is expected to
// already be sanitized by the caller (internal/llm.Sanitize) before it
// reaches this Validator.
func (v *Validator) Validate(ctx context.Context, input cerberus.ValidationInput) (cerberus.ValidationResult, error) {
	tmpl, err := v.prompts.Get(v.promptTemplateID)
	if err != nil {
		return llm.FallbackResult(fmt.Sprintf("llamacpp: prompt template unavailable: %v", err)), err
	}

	renderedPrompt, err := tmpl.Render(input)
	if err != nil {
		return llm.FallbackResult(fmt.Sprintf("llamacpp: prompt rendering failed: %v", err)), err
	}

	attempt := func(attemptCtx context.Context) ([]byte, error) {
		return v.complete(attemptCtx, renderedPrompt)
	}

	result, err := llm.ParseValidationResultWithRetry(ctx, v.maxAttempts, attempt)
	if err != nil {
		return result, fmt.Errorf("llamacpp: validate: %w", err)
	}
	return result, nil
}

// complete performs a single HTTP round trip against the server's chat
// completions endpoint and returns the assistant message content,
// which internal/llm.ParseValidationResult(WithRetry) is responsible
// for schema-validating. complete itself never parses the model's
// answer beyond unwrapping the OpenAI-compatible envelope.
func (v *Validator) complete(ctx context.Context, renderedPrompt string) ([]byte, error) {
	reqBody := chatCompletionRequest{
		Model: v.model,
		Messages: []chatMessage{
			{Role: "user", Content: renderedPrompt},
		},
		Temperature: v.temperature,
		Stream:      false,
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("llamacpp: encoding request: %w", err)
	}

	endpoint := v.baseURL + defaultChatCompletionsPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("llamacpp: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := v.httpClient.Do(httpReq)
	if err != nil {
		// http.Client wraps context.Canceled/DeadlineExceeded; surface
		// it as-is so callers (and ParseValidationResultWithRetry's
		// ctx.Err() check between attempts) can detect cancellation.
		return nil, fmt.Errorf("llamacpp: request to %s failed: %w", endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // 8 MiB cap against a misbehaving server.
	if err != nil {
		return nil, fmt.Errorf("llamacpp: reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("llamacpp: server returned HTTP %d: %s", resp.StatusCode, truncate(string(body), 500))
	}

	var parsed chatCompletionResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("llamacpp: decoding chat completion envelope: %w", err)
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("llamacpp: server reported error: %s", truncate(parsed.Error.Message, 500))
	}
	if len(parsed.Choices) == 0 {
		return nil, errors.New("llamacpp: response contained no choices")
	}

	return []byte(parsed.Choices[0].Message.Content), nil
}

// truncate bounds a string used in an error message so an oversized or
// unexpected server response can never blow up log/error output.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}
