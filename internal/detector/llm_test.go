package detector_test

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/HaK0exe/cerberus/internal/detector"
	"github.com/HaK0exe/cerberus/internal/rules"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// mustRule builds a single-rule CompiledRule matching SECRET_<8 alnum
// chars>, with no entropy/keyword adjustments, so its deterministic
// score is exactly the confidence given — letting tests place a
// candidate precisely in a band without depending on the real rule
// corpus or entropy heuristics.
func mustRule(t *testing.T, id string, confidence float64) rules.CompiledRule {
	t.Helper()
	return rules.CompiledRule{
		Rule: cerberus.Rule{
			ID:         id,
			Name:       id,
			Regex:      `SECRET_[A-Za-z0-9]{8}`,
			Severity:   cerberus.SeverityHigh,
			Confidence: confidence,
		},
		Pattern: regexp.MustCompile(`SECRET_[A-Za-z0-9]{8}`),
	}
}

// panicValidator fails the test immediately if Validate is ever
// called — used to assert that BandFinding/BandIgnore candidates never
// reach the LLM stage.
type panicValidator struct{ t *testing.T }

func (p panicValidator) Validate(ctx context.Context, in cerberus.ValidationInput) (cerberus.ValidationResult, error) {
	p.t.Fatal("Validator.Validate called for a candidate that should have bypassed the LLM stage")
	return cerberus.ValidationResult{}, nil
}

// fakeValidator returns a canned result/error and records the last
// input it was called with, so tests can inspect exactly what was sent
// to it.
type fakeValidator struct {
	result cerberus.ValidationResult
	err    error

	calls    int
	lastCall cerberus.ValidationInput
}

func (f *fakeValidator) Validate(ctx context.Context, in cerberus.ValidationInput) (cerberus.ValidationResult, error) {
	f.calls++
	f.lastCall = in
	return f.result, f.err
}

func artifactWithSecret(secret string) cerberus.Artifact {
	return cerberus.Artifact{
		SourceType: cerberus.SourceFile,
		Path:       "config/app.env",
		Content:    []byte("token = " + secret + " # do not commit\n"),
	}
}

func TestDetect_HighConfidenceBandBypassesValidator(t *testing.T) {
	rule := mustRule(t, "test-high-confidence", 0.95) // >= ThresholdFinding
	d := detector.New([]rules.CompiledRule{rule}, nil, detector.WithValidator(panicValidator{t: t}))

	findings, err := d.Detect(context.Background(), artifactWithSecret("SECRET_ABCD1234"))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Confidence != 0.95 {
		t.Errorf("expected deterministic confidence 0.95 unchanged, got %f", findings[0].Confidence)
	}
}

func TestDetect_IgnoreBandBypassesValidator(t *testing.T) {
	rule := mustRule(t, "test-ignore-band", 0.10) // < ThresholdIgnore
	d := detector.New([]rules.CompiledRule{rule}, nil,
		detector.WithValidator(panicValidator{t: t}),
	)

	findings, err := d.Detect(context.Background(), artifactWithSecret("SECRET_ABCD1234"))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings emitted for the ignore band, got %d", len(findings))
	}
}

func TestDetect_LLMReviewBandCallsValidatorAndAdjustsScore(t *testing.T) {
	rule := mustRule(t, "test-llm-review", 0.75) // inside [0.70, 0.90)
	fv := &fakeValidator{result: cerberus.ValidationResult{
		Classification: cerberus.ClassificationLikelySecret,
		Confidence:     0.9,
		Reason:         "looks like a live credential",
	}}
	d := detector.New([]rules.CompiledRule{rule}, nil, detector.WithValidator(fv))

	findings, err := d.Detect(context.Background(), artifactWithSecret("SECRET_ABCD1234"))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if fv.calls != 1 {
		t.Fatalf("expected exactly 1 Validator call, got %d", fv.calls)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the llm_review candidate to be emitted after a likely_secret verdict, got %d findings", len(findings))
	}
	f := findings[0]
	if f.Confidence < detector.ThresholdLLMReview || f.Confidence >= detector.ThresholdFinding {
		t.Errorf("expected adjusted confidence to stay within the llm_review band [%.2f, %.2f), got %f",
			detector.ThresholdLLMReview, detector.ThresholdFinding, f.Confidence)
	}
	if f.Confidence <= 0.75 {
		t.Errorf("expected a likely_secret verdict to raise the score above the deterministic 0.75, got %f", f.Confidence)
	}
	if f.Metadata["llm_classification"] != string(cerberus.ClassificationLikelySecret) {
		t.Errorf("expected llm_classification metadata to be recorded, got %q", f.Metadata["llm_classification"])
	}
}

func TestDetect_LLMReviewBandLikelyFalsePositiveIsDropped(t *testing.T) {
	rule := mustRule(t, "test-llm-review-fp", 0.80)
	fv := &fakeValidator{result: cerberus.ValidationResult{
		Classification: cerberus.ClassificationLikelyFalsePos,
		Confidence:     0.95,
		Reason:         "matches a documented test fixture pattern",
	}}
	// Even with a low minEmitBand that would otherwise surface the raw
	// llm_review candidate, an explicit likely_false_positive verdict
	// must suppress emission.
	d := detector.New([]rules.CompiledRule{rule}, nil,
		detector.WithValidator(fv),
		detector.WithMinEmitBand(detector.BandLowConfidence),
	)

	findings, err := d.Detect(context.Background(), artifactWithSecret("SECRET_ABCD1234"))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected likely_false_positive verdict to suppress emission, got %d findings", len(findings))
	}
}

func TestDetect_ValidatorFailureFallsBackToDeterministicScore(t *testing.T) {
	rule := mustRule(t, "test-llm-fallback", 0.75)
	fv := &fakeValidator{err: errors.New("boom: model unreachable")}
	// Default minEmitBand is BandFinding, so llm_review candidates are
	// dropped unless the Validator explicitly promotes them — same
	// behavior a Detector with no Validator at all would have.
	d := detector.New([]rules.CompiledRule{rule}, nil, detector.WithValidator(fv))

	findings, err := d.Detect(context.Background(), artifactWithSecret("SECRET_ABCD1234"))
	if err != nil {
		t.Fatalf("Detect must not return an error when the Validator fails: %v", err)
	}
	if fv.calls != 1 {
		t.Fatalf("expected exactly 1 Validator call, got %d", fv.calls)
	}
	if len(findings) != 0 {
		t.Fatalf("expected a failed Validator call to fall back to default (non-emitting) behavior, got %d findings", len(findings))
	}
}

func TestDetect_NoValidatorConfiguredPreservesSprint1Behavior(t *testing.T) {
	rule := mustRule(t, "test-no-validator", 0.75)
	d := detector.New([]rules.CompiledRule{rule}, nil) // no WithValidator at all

	findings, err := d.Detect(context.Background(), artifactWithSecret("SECRET_ABCD1234"))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected llm_review band to be dropped with no Validator configured, got %d findings", len(findings))
	}
}

func TestDetect_ValidatorNeverReceivesRawSecret(t *testing.T) {
	const secret = "SECRET_ABCD1234"
	rule := mustRule(t, "test-sanitize", 0.75)
	fv := &fakeValidator{result: cerberus.ValidationResult{
		Classification: cerberus.ClassificationUncertain,
		Confidence:     0.5,
	}}
	d := detector.New([]rules.CompiledRule{rule}, nil, detector.WithValidator(fv))

	if _, err := d.Detect(context.Background(), artifactWithSecret(secret)); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if fv.calls != 1 {
		t.Fatalf("expected exactly 1 Validator call, got %d", fv.calls)
	}
	if strings.Contains(fv.lastCall.RedactedContext, secret) {
		t.Fatalf("raw secret value leaked into the context sent to the Validator: %q", fv.lastCall.RedactedContext)
	}
	if !strings.Contains(fv.lastCall.RedactedContext, "[REDACTED-SECRET]") {
		t.Errorf("expected the sanitized placeholder in the context sent to the Validator, got %q", fv.lastCall.RedactedContext)
	}
}
