package cerberus

import "context"

// Detector runs the detection pipeline against a single Artifact and
// returns zero or more Findings. Implementations must never emit a
// Finding containing a raw secret value.
type Detector interface {
	Detect(ctx context.Context, artifact Artifact) ([]Finding, error)
}

// ValidationInput is what gets sent to a Validator (typically a local
// LLM) to classify an ambiguous Candidate. It must be pre-sanitized:
// no raw secret value, only redacted context.
type ValidationInput struct {
	RuleID          string
	Entropy         float64
	Path            string
	RedactedContext string
}

// ValidationClassification is the LLM's verdict on a candidate.
type ValidationClassification string

const (
	ClassificationLikelySecret   ValidationClassification = "likely_secret"
	ClassificationLikelyFalsePos ValidationClassification = "likely_false_positive"
	ClassificationUncertain      ValidationClassification = "uncertain"
)

// ValidationResult is the structured, schema-validated output of a
// Validator call.
type ValidationResult struct {
	Classification ValidationClassification
	Confidence     float64
	Reason         string
}

// Validator is implemented by LLM-backed secret classifiers (Ollama,
// llama.cpp, ...). A Validator is never authoritative: see
// docs/architecture/llm-non-sovereign.md.
type Validator interface {
	Validate(ctx context.Context, input ValidationInput) (ValidationResult, error)
}

// ScanOptions configures a single scan run across scanners.
type ScanOptions struct {
	Depth          int
	MaxPages       int
	RateLimit      float64
	Concurrency    int
	AllowedDomains []string
	ExcludePaths   []string
	RespectRobots  bool
	ScanJavaScript bool

	History bool
	Staged  bool
	Branch  string
}

// JobQueue abstracts the distributed work queue used to fan scan jobs
// out to workers (in-memory for local/dev, SQS in AWS deployments).
type JobQueue interface {
	Publish(ctx context.Context, queue string, payload []byte) error
	Consume(ctx context.Context, queue string) (<-chan []byte, error)
}
