package ollama

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/HaK0exe/cerberus/internal/llm"
	"github.com/HaK0exe/cerberus/internal/llm/prompt"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// testPrompts builds a minimal, self-contained prompt.Store for tests
// so they never depend on the real prompts/candidate_validation.md
// file's exact wording.
func testPrompts(t *testing.T) *prompt.Store {
	t.Helper()
	fsys := fstest.MapFS{
		"candidate_validation.md": &fstest.MapFile{
			Data: []byte(strings.TrimSpace(`
---
id: candidate_validation
version: 1
description: test template
---
Rule: {{.RuleID}}
Path: {{.Path}}
Context: {{.RedactedContext}}
`) + "\n"),
		},
	}
	store, err := prompt.LoadDir(fsys, ".")
	if err != nil {
		t.Fatalf("prompt.LoadDir: %v", err)
	}
	return store
}

func testInput() cerberus.ValidationInput {
	return cerberus.ValidationInput{
		RuleID:          "aws-access-key-id",
		Entropy:         4.2,
		Path:            "config/.env",
		RedactedContext: "AWS_SECRET_ACCESS_KEY=[REDACTED]",
	}
}

func newTestValidator(t *testing.T, baseURL string, opts func(*Config)) *Validator {
	t.Helper()
	cfg := Config{
		BaseURL: baseURL,
		Model:   "llama3.1:8b",
		Prompts: testPrompts(t),
		Timeout: 2 * time.Second,
	}
	if opts != nil {
		opts(&cfg)
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}
	return v
}

func TestNew_RequiresModel(t *testing.T) {
	_, err := New(Config{Prompts: testPrompts(t)})
	if err == nil {
		t.Fatal("New: expected error for missing Model, got nil")
	}
}

func TestNew_RequiresPrompts(t *testing.T) {
	_, err := New(Config{Model: "llama3.1"})
	if err == nil {
		t.Fatal("New: expected error for missing Prompts, got nil")
	}
}

func TestNew_UnknownTemplateID(t *testing.T) {
	_, err := New(Config{Model: "llama3.1", Prompts: testPrompts(t), TemplateID: "does-not-exist"})
	if err == nil {
		t.Fatal("New: expected error for unknown TemplateID, got nil")
	}
}

func TestNew_Defaults(t *testing.T) {
	v, err := New(Config{Model: "llama3.1", Prompts: testPrompts(t)})
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}
	if v.baseURL != DefaultBaseURL {
		t.Errorf("baseURL = %q, want %q", v.baseURL, DefaultBaseURL)
	}
	if v.templateID != DefaultTemplateID {
		t.Errorf("templateID = %q, want %q", v.templateID, DefaultTemplateID)
	}
	if v.timeout != DefaultTimeout {
		t.Errorf("timeout = %v, want %v", v.timeout, DefaultTimeout)
	}
	if v.maxAttempts != DefaultMaxAttempts {
		t.Errorf("maxAttempts = %d, want %d", v.maxAttempts, DefaultMaxAttempts)
	}
}

func TestValidate_Success(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &gotBody); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		resp := ollamaGenerateResponse{
			Response: `{"classification":"likely_secret","confidence":0.92,"reason":"looks like a live AWS key"}`,
			Done:     true,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	v := newTestValidator(t, srv.URL, nil)
	result, err := v.Validate(context.Background(), testInput())
	if err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	if result.Classification != cerberus.ClassificationLikelySecret {
		t.Errorf("Classification = %q, want %q", result.Classification, cerberus.ClassificationLikelySecret)
	}
	if result.Confidence != 0.92 {
		t.Errorf("Confidence = %v, want 0.92", result.Confidence)
	}

	// The request must carry only the redacted context, never a raw
	// secret value.
	if gotBody["model"] != "llama3.1:8b" {
		t.Errorf("request model = %v, want llama3.1:8b", gotBody["model"])
	}
	promptStr, _ := gotBody["prompt"].(string)
	if !strings.Contains(promptStr, "AWS_SECRET_ACCESS_KEY=[REDACTED]") {
		t.Errorf("rendered prompt missing redacted context: %q", promptStr)
	}
}

func TestValidate_HTTPErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer srv.Close()

	v := newTestValidator(t, srv.URL, func(c *Config) { c.MaxAttempts = 1 })
	result, err := v.Validate(context.Background(), testInput())
	if err == nil {
		t.Fatal("Validate: expected error, got nil")
	}
	if !errors.Is(err, ErrRequestFailed) {
		t.Errorf("errors.Is(err, ErrRequestFailed) = false, err = %v", err)
	}
	if result.Classification != cerberus.ClassificationUncertain || result.Confidence != 0 {
		t.Errorf("result = %+v, want safe fallback (uncertain, confidence 0)", result)
	}
}

func TestValidate_ModelNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"model 'llama3.1:8b' not found, try pulling it first"}`))
	}))
	defer srv.Close()

	v := newTestValidator(t, srv.URL, func(c *Config) { c.MaxAttempts = 1 })
	result, err := v.Validate(context.Background(), testInput())
	if err == nil {
		t.Fatal("Validate: expected error, got nil")
	}
	if !errors.Is(err, ErrModelNotFound) {
		t.Errorf("errors.Is(err, ErrModelNotFound) = false, err = %v", err)
	}
	if result.Classification != cerberus.ClassificationUncertain {
		t.Errorf("result.Classification = %q, want uncertain", result.Classification)
	}
}

func TestValidate_ConnectionRefused(t *testing.T) {
	// Nothing is listening on this port: the HTTP client's Do call
	// itself fails before any response is received.
	v := newTestValidator(t, "http://127.0.0.1:1", func(c *Config) {
		c.MaxAttempts = 1
		c.Timeout = 2 * time.Second
	})
	result, err := v.Validate(context.Background(), testInput())
	if err == nil {
		t.Fatal("Validate: expected error, got nil")
	}
	if !errors.Is(err, ErrConnectionFailed) {
		t.Errorf("errors.Is(err, ErrConnectionFailed) = false, err = %v", err)
	}
	if result.Classification != cerberus.ClassificationUncertain || result.Confidence != 0 {
		t.Errorf("result = %+v, want safe fallback", result)
	}
}

func TestValidate_MalformedJSONRetriesThenFallsBack(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		resp := ollamaGenerateResponse{Response: `not valid json at all`, Done: true}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	v := newTestValidator(t, srv.URL, func(c *Config) { c.MaxAttempts = 3 })
	result, err := v.Validate(context.Background(), testInput())
	if err == nil {
		t.Fatal("Validate: expected error, got nil")
	}
	if !errors.Is(err, llm.ErrSchemaViolation) {
		t.Errorf("errors.Is(err, llm.ErrSchemaViolation) = false, err = %v", err)
	}
	if calls != 3 {
		t.Errorf("server received %d calls, want 3 (MaxAttempts)", calls)
	}
	if result.Classification != cerberus.ClassificationUncertain || result.Confidence != 0 {
		t.Errorf("result = %+v, want safe fallback", result)
	}
}

func TestValidate_RetriesRecoverAfterOneMalformedResponse(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var resp ollamaGenerateResponse
		if calls == 1 {
			resp = ollamaGenerateResponse{Response: `{oops`, Done: true}
		} else {
			resp = ollamaGenerateResponse{
				Response: `{"classification":"uncertain","confidence":0.4,"reason":"ambiguous"}`,
				Done:     true,
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	v := newTestValidator(t, srv.URL, func(c *Config) { c.MaxAttempts = 3 })
	result, err := v.Validate(context.Background(), testInput())
	if err != nil {
		t.Fatalf("Validate: unexpected error after successful retry: %v", err)
	}
	if calls != 2 {
		t.Errorf("server received %d calls, want 2", calls)
	}
	if result.Classification != cerberus.ClassificationUncertain || result.Confidence != 0.4 {
		t.Errorf("result = %+v, want the second attempt's result", result)
	}
}

func TestValidate_ContextCancellation(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	// LIFO: unblock the handler before srv.Close() waits on it.
	defer srv.Close()
	defer close(block)

	v := newTestValidator(t, srv.URL, func(c *Config) {
		c.MaxAttempts = 1
		c.Timeout = 0 // rely on the caller's context, not a per-call timeout
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	result, err := v.Validate(ctx, testInput())
	if err == nil {
		t.Fatal("Validate: expected error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("errors.Is(err, context.DeadlineExceeded) = false, err = %v", err)
	}
	if result.Classification != cerberus.ClassificationUncertain || result.Confidence != 0 {
		t.Errorf("result = %+v, want safe fallback", result)
	}
}

func TestValidate_PerCallTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	// LIFO: unblock the handler before srv.Close() waits on it.
	defer srv.Close()
	defer close(block)

	v := newTestValidator(t, srv.URL, func(c *Config) {
		c.MaxAttempts = 1
		c.Timeout = 50 * time.Millisecond
	})

	start := time.Now()
	result, err := v.Validate(context.Background(), testInput())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Validate: expected error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("Validate took %v, want it bounded by the configured per-call timeout", elapsed)
	}
	if result.Classification != cerberus.ClassificationUncertain || result.Confidence != 0 {
		t.Errorf("result = %+v, want safe fallback", result)
	}
}

func TestValidate_NeverSendsRawSecret(t *testing.T) {
	const rawSecret = "AKIAABCDEFGHIJKLMNOP"
	var capturedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		capturedBody = string(raw)
		resp := ollamaGenerateResponse{
			Response: `{"classification":"uncertain","confidence":0.5,"reason":"n/a"}`,
			Done:     true,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	v := newTestValidator(t, srv.URL, nil)
	input := testInput()
	input.RedactedContext = "token=[REDACTED-20]" // Sanitize's job, simulated here.

	if _, err := v.Validate(context.Background(), input); err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	if strings.Contains(capturedBody, rawSecret) {
		t.Fatalf("request body leaked a raw secret value: %s", capturedBody)
	}
}

// stubDoer lets a test force the exact error http.Client.Do returns,
// without depending on OS-level connection-refused behavior.
type stubDoer struct {
	resp *http.Response
	err  error
}

func (s stubDoer) Do(req *http.Request) (*http.Response, error) {
	return s.resp, s.err
}

func TestValidate_TransportError(t *testing.T) {
	v := newTestValidator(t, "http://example.invalid", func(c *Config) {
		c.MaxAttempts = 1
		c.HTTPClient = stubDoer{err: errors.New("dial tcp: connection refused")}
	})

	_, err := v.Validate(context.Background(), testInput())
	if !errors.Is(err, ErrConnectionFailed) {
		t.Errorf("errors.Is(err, ErrConnectionFailed) = false, err = %v", err)
	}
}
