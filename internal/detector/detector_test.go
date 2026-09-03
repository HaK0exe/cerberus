package detector_test

import (
	"context"
	"os"
	"testing"

	"github.com/HaK0exe/cerberus/internal/detector"
	"github.com/HaK0exe/cerberus/internal/policy"
	"github.com/HaK0exe/cerberus/internal/rules"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func loadTestRules(t *testing.T) []rules.CompiledRule {
	t.Helper()
	compiled, err := rules.LoadDir(os.DirFS("../.."), "rules")
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}
	if len(compiled) == 0 {
		t.Fatal("expected at least one rule to load")
	}
	return compiled
}

func newFingerprinter(t *testing.T) *policy.Fingerprinter {
	t.Helper()
	fp, err := policy.NewFingerprinter([]byte("test-key-not-for-production"))
	if err != nil {
		t.Fatalf("new fingerprinter: %v", err)
	}
	return fp
}

func TestDetect_AWSAccessKey(t *testing.T) {
	d := detector.New(loadTestRules(t), newFingerprinter(t), detector.WithMinEmitBand(detector.BandLowConfidence))

	artifact := cerberus.Artifact{
		SourceType: cerberus.SourceFile,
		Path:       "config/prod.env",
		Content:    []byte("aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n"),
	}

	findings, err := d.Detect(context.Background(), artifact)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "aws-access-key-id" {
			found = true
			if f.Fingerprint == "" {
				t.Error("expected non-empty fingerprint")
			}
			if f.MaskedPrefix != "AKIA****************" {
				t.Errorf("unexpected masked prefix: %q", f.MaskedPrefix)
			}
		}
	}
	if !found {
		t.Fatal("expected aws-access-key-id finding")
	}
}

func TestDetect_PlaceholderSuppressed(t *testing.T) {
	d := detector.New(loadTestRules(t), newFingerprinter(t), detector.WithMinEmitBand(detector.BandFinding))

	artifact := cerberus.Artifact{
		SourceType: cerberus.SourceFile,
		Path:       "docs/example.md",
		Content:    []byte("aws_access_key_id = AKIAABCDEFGHIJKLMNOP # example placeholder\n"),
	}

	findings, err := d.Detect(context.Background(), artifact)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	for _, f := range findings {
		if f.RuleID == "aws-access-key-id" {
			t.Fatalf("expected placeholder context to suppress the finding at BandFinding threshold, got confidence=%.2f", f.Confidence)
		}
	}
}

func TestDetect_NoFindingsOnCleanContent(t *testing.T) {
	d := detector.New(loadTestRules(t), newFingerprinter(t))

	artifact := cerberus.Artifact{
		SourceType: cerberus.SourceFile,
		Path:       "README.md",
		Content:    []byte("Cerberus detects exposed secrets in Git repositories and websites.\n"),
	}

	findings, err := d.Detect(context.Background(), artifact)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
