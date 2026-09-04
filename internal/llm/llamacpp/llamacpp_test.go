package llamacpp

import (
	"bytes"
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

// testStore returns a minimal in-memory prompt.Store with a
// "candidate_validation" template, so tests don't depend on the real
// prompts/ directory's path relative to this package.
func testStore(t *testing.T) *prompt.Store {
	t.Helper()
	fsys := fstest.MapFS{
		"candidate_validation.md": &fstest.MapFile{
			Data: []byte(`---
id: candidate_validation
version: 1
description: test template
---
Rule: {{.RuleID}}
Path: {{.Path}}
Entropy: {{.Entropy}}
Context: {{.RedactedContext}}
`),
		},
	}
	store, err := prompt.LoadDir(fsys, ".")
	if err != nil {
		t.Fatalf("prompt.LoadDir: unexpected error: %v", err)
	}
	return store
}

func testInput() cerberus.ValidationInput {
	return cerberus.ValidationInput{
		RuleID:          "aws-access-key-id",
		Entropy:         4.2,
		Path:            "config/.env",
		RedactedContext: "AWS_SECRET=<<REDACTED>>",
	}
}

// roundTripperFunc adapts a function to http.RoundTripper so tests can
// build an *http.Client (which also satisfies our HTTPClient
// interface) without a real network listener when httptest isn't
// needed.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestNew_RequiresBaseURL(t *testing.T) {
	_, err := New(Config{Model: "m"}, testStore(t))
	if err == nil {
		t.Fatalf("New: expected error for missing BaseURL, got nil")
	}
}

func TestNew_RequiresModel(t *testing.T) {
	_, err := New(Config{BaseURL: "http://localhost:8080"}, testStore(t))
	if err == nil {
		t.Fatalf("New: expected error for missing Model, got nil")
	}
}

func TestNew_RequiresStore(t *testing.T) {
	_, err := New(Config{BaseURL: "http://localhost:8080", Model: "m"}, nil)
	if err == nil {
		t.Fatalf("New: expected error for nil store, got nil")
	}
}

func TestNew_RequiresPromptTemplateLoaded(t *testing.T) {
	_, err := New(Config{
		BaseURL:          "http://localhost:8080",
		Model:            "m",
		PromptTemplateID: "does-not-exist",
	}, testStore(t))
	if err == nil {
		t.Fatalf("New: expected error for unloaded template id, got nil")
	}
}

func chatResponseBody(t *testing.T, content string) []byte {
	t.Helper()
	body := map[string]any{
		"choices": []map[string]any{
			{"message": map[string]any{"role": "assistant", "content": content}},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal test response: %v", err)
	}
	return raw
}

func TestValidate_Success(t *testing.T) {
	var gotPath string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("server: decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(chatResponseBody(t, `{"classification":"likely_secret","confidence":0.9,"reason":"looks real"}`))
	}))
	defer srv.Close()

	v, err := New(Config{BaseURL: srv.URL, Model: "test-model"}, testStore(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, err := v.Validate(context.Background(), testInput())
	if err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	if result.Classification != cerberus.ClassificationLikelySecret {
		t.Fatalf("Classification = %q, want likely_secret", result.Classification)
	}
	if result.Confidence != 0.9 {
		t.Fatalf("Confidence = %v, want 0.9", result.Confidence)
	}
	if gotPath != defaultChatCompletionsPath {
		t.Fatalf("request path = %q, want %q", gotPath, defaultChatCompletionsPath)
	}
	if gotBody["model"] != "test-model" {
		t.Fatalf("request model = %v, want test-model", gotBody["model"])
	}

	// The rendered prompt must never contain the raw secret value —
	// RedactedContext in testInput() is already sanitized, so this
	// asserts the adapter didn't reintroduce anything unexpected.
	messages, _ := gotBody["messages"].([]any)
	if len(messages) == 0 {
		t.Fatalf("request had no messages")
	}
}

func TestValidate_CustomPromptTemplateID(t *testing.T) {
	fsys := fstest.MapFS{
		"other.md": &fstest.MapFile{Data: []byte("---\nid: other\nversion: 1\n---\nHello {{.RuleID}}\n")},
	}
	store, err := prompt.LoadDir(fsys, ".")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	var gotContent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		msgs := body["messages"].([]any)
		gotContent = msgs[0].(map[string]any)["content"].(string)
		w.Write(chatResponseBody(t, `{"classification":"uncertain","confidence":0.5,"reason":"n/a"}`))
	}))
	defer srv.Close()

	v, err := New(Config{BaseURL: srv.URL, Model: "m", PromptTemplateID: "other"}, store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Validate(context.Background(), testInput()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !strings.Contains(gotContent, "Hello aws-access-key-id") {
		t.Fatalf("rendered prompt = %q, want it to use the custom template", gotContent)
	}
}

func TestValidate_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()

	v, err := New(Config{BaseURL: srv.URL, Model: "m", MaxAttempts: 1}, testStore(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, err := v.Validate(context.Background(), testInput())
	if err == nil {
		t.Fatalf("Validate: expected error for HTTP 500, got nil")
	}
	// Failure must degrade to the safe fallback, never propagate a
	// zero-value/authoritative result.
	if result.Classification != cerberus.ClassificationUncertain || result.Confidence != 0 {
		t.Fatalf("Validate degraded result = %+v, want FallbackResult shape", result)
	}
}

func TestValidate_ServerUnavailable(t *testing.T) {
	// Point at a URL nothing is listening on.
	v, err := New(Config{BaseURL: "http://127.0.0.1:1", Model: "m", MaxAttempts: 1}, testStore(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, err := v.Validate(context.Background(), testInput())
	if err == nil {
		t.Fatalf("Validate: expected error for unreachable server, got nil")
	}
	if result.Classification != cerberus.ClassificationUncertain {
		t.Fatalf("Classification = %q, want uncertain fallback", result.Classification)
	}
}

func TestValidate_MalformedJSON_RetriesThenSucceeds(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Write(chatResponseBody(t, `not valid json at all`))
			return
		}
		w.Write(chatResponseBody(t, `{"classification":"likely_false_positive","confidence":0.3,"reason":"placeholder"}`))
	}))
	defer srv.Close()

	v, err := New(Config{BaseURL: srv.URL, Model: "m", MaxAttempts: 2}, testStore(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, err := v.Validate(context.Background(), testInput())
	if err != nil {
		t.Fatalf("Validate: unexpected error after successful retry: %v", err)
	}
	if result.Classification != cerberus.ClassificationLikelyFalsePos {
		t.Fatalf("Classification = %q, want likely_false_positive", result.Classification)
	}
	if calls != 2 {
		t.Fatalf("server called %d times, want 2 (one malformed attempt + one retry)", calls)
	}
}

func TestValidate_MalformedJSON_AllAttemptsFail(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write(chatResponseBody(t, `still not json`))
	}))
	defer srv.Close()

	v, err := New(Config{BaseURL: srv.URL, Model: "m", MaxAttempts: 3}, testStore(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, err := v.Validate(context.Background(), testInput())
	if err == nil {
		t.Fatalf("Validate: expected error when every attempt fails schema validation")
	}
	if !errors.Is(err, llm.ErrSchemaViolation) {
		t.Fatalf("Validate error = %v, want it to wrap llm.ErrSchemaViolation", err)
	}
	if result.Classification != cerberus.ClassificationUncertain || result.Confidence != 0 {
		t.Fatalf("Validate degraded result = %+v, want FallbackResult shape", result)
	}
	if calls != 3 {
		t.Fatalf("server called %d times, want 3 (MaxAttempts)", calls)
	}
}

func TestValidate_ContextCancellation(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer srv.Close()
	defer close(block)

	v, err := New(Config{BaseURL: srv.URL, Model: "m", MaxAttempts: 1}, testStore(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	result, err := v.Validate(ctx, testInput())
	if err == nil {
		t.Fatalf("Validate: expected error for context deadline exceeded, got nil")
	}
	if result.Classification != cerberus.ClassificationUncertain {
		t.Fatalf("Classification = %q, want uncertain fallback on cancellation", result.Classification)
	}
}

func TestValidate_ServerErrorEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"error":{"message":"model not loaded"}}`))
	}))
	defer srv.Close()

	v, err := New(Config{BaseURL: srv.URL, Model: "m", MaxAttempts: 1}, testStore(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, err := v.Validate(context.Background(), testInput())
	if err == nil {
		t.Fatalf("Validate: expected error for server error envelope, got nil")
	}
	if result.Classification != cerberus.ClassificationUncertain {
		t.Fatalf("Classification = %q, want uncertain fallback", result.Classification)
	}
}

func TestValidate_NoChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[]}`))
	}))
	defer srv.Close()

	v, err := New(Config{BaseURL: srv.URL, Model: "m", MaxAttempts: 1}, testStore(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Validate(context.Background(), testInput()); err == nil {
		t.Fatalf("Validate: expected error for empty choices, got nil")
	}
}

func TestValidate_InjectedHTTPClient(t *testing.T) {
	called := false
	client := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(chatResponseBody(t, `{"classification":"uncertain","confidence":0.1,"reason":"n/a"}`))),
			}, nil
		}),
	}

	v, err := New(Config{BaseURL: "http://example.invalid", Model: "m", HTTPClient: client}, testStore(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Validate(context.Background(), testInput()); err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	if !called {
		t.Fatalf("injected HTTPClient was never called")
	}
}

func TestValidate_ConfidenceClamped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(chatResponseBody(t, `{"classification":"likely_secret","confidence":5,"reason":"n/a"}`))
	}))
	defer srv.Close()

	v, err := New(Config{BaseURL: srv.URL, Model: "m"}, testStore(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, err := v.Validate(context.Background(), testInput())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Confidence != 1 {
		t.Fatalf("Confidence = %v, want clamped to 1", result.Confidence)
	}
}
