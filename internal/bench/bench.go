package bench

import (
	"context"
	"crypto/rand"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/HaK0exe/cerberus/internal/detector"
	"github.com/HaK0exe/cerberus/internal/policy"
	"github.com/HaK0exe/cerberus/internal/rules"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// Report is the outcome of running a corpus through a Detector.
//
// Precision/Recall/F1/FalsePositiveRate are computed against strict
// "did Detect emit a Finding" outcomes — this package deliberately
// does not measure allocations, LLM call counts, or LLM latency (see
// the package doc comment): those require testing.B-style
// instrumentation and a live/fake Validator this slice doesn't wire
// up, and a Report claiming numbers for them without measuring would
// be worse than a Report that simply omits the field.
type Report struct {
	TruePositives  int
	FalsePositives int
	TrueNegatives  int
	FalseNegatives int

	Precision         float64
	Recall            float64
	F1                float64
	FalsePositiveRate float64

	Duration         time.Duration
	SamplesPerSecond float64
}

// Run executes d.Detect against every sample and classifies the
// outcome against its ExpectedResult:
//
//   - Expected.ExpectFindings and a matching Finding found  -> true positive
//   - Expected.ExpectFindings and no matching Finding found -> false negative
//   - !Expected.ExpectFindings and any Finding found        -> false positive
//   - !Expected.ExpectFindings and no Finding found         -> true negative
//
// "matching" means: if Expected.RuleID is set, at least one Finding
// has that RuleID and Confidence >= Expected.MinConfidence; if unset,
// any Finding at all counts.
func Run(ctx context.Context, d *detector.Detector, samples []Sample) (Report, error) {
	var r Report
	start := time.Now()

	for _, s := range samples {
		artifact := cerberus.Artifact{
			SourceType: cerberus.SourceFile,
			Path:       s.Path,
			Content:    s.Content,
		}

		findings, err := d.Detect(ctx, artifact)
		if err != nil {
			return Report{}, fmt.Errorf("detecting on %s: %w", s.Path, err)
		}

		matched := sampleMatches(s.Expected, findings)

		switch {
		case s.Expected.ExpectFindings && matched:
			r.TruePositives++
		case s.Expected.ExpectFindings && !matched:
			r.FalseNegatives++
		case !s.Expected.ExpectFindings && len(findings) > 0:
			r.FalsePositives++
		default:
			r.TrueNegatives++
		}
	}

	r.Duration = time.Since(start)
	if r.Duration > 0 {
		r.SamplesPerSecond = float64(len(samples)) / r.Duration.Seconds()
	}
	r.Precision, r.Recall, r.F1, r.FalsePositiveRate = computeRates(r.TruePositives, r.FalsePositives, r.TrueNegatives, r.FalseNegatives)

	return r, nil
}

func sampleMatches(expected ExpectedResult, findings []cerberus.Finding) bool {
	if !expected.ExpectFindings {
		return len(findings) == 0
	}
	for _, f := range findings {
		if expected.RuleID != "" && f.RuleID != expected.RuleID {
			continue
		}
		if f.Confidence < expected.MinConfidence {
			continue
		}
		return true
	}
	return false
}

func computeRates(tp, fp, tn, fn int) (precision, recall, f1, fpr float64) {
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		recall = float64(tp) / float64(tp+fn)
	}
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	if fp+tn > 0 {
		fpr = float64(fp) / float64(fp+tn)
	}
	return precision, recall, f1, fpr
}

// Compare renders a human-readable BEFORE/AFTER/Delta comparison
// between two Reports — the spec's explicit ask: a rule or scoring
// change should be able to show its effect, not just a raw number.
func Compare(before, after Report) string {
	var b strings.Builder

	fmt.Fprintf(&b, "BEFORE\n\n%s\n", before.String())
	fmt.Fprintf(&b, "AFTER\n\n%s\n", after.String())
	fmt.Fprintf(&b, "DELTA\n\n")
	fmt.Fprintf(&b, "Precision: %+.1f%%\n", (after.Precision-before.Precision)*100)
	fmt.Fprintf(&b, "Recall:    %+.1f%%\n", (after.Recall-before.Recall)*100)
	fmt.Fprintf(&b, "F1:        %+.1f%%\n", (after.F1-before.F1)*100)
	fmt.Fprintf(&b, "FP:        %+d\n", after.FalsePositives-before.FalsePositives)
	fmt.Fprintf(&b, "FN:        %+d\n", after.FalseNegatives-before.FalseNegatives)

	return b.String()
}

// String renders a single Report as the BEFORE/AFTER block shape.
func (r Report) String() string {
	return fmt.Sprintf(
		"Precision: %.1f%%\nRecall:    %.1f%%\nF1:        %.1f%%\nFP:        %d\nFN:        %d\nTP:        %d\nTN:        %d\nDuration:  %s (%.0f samples/sec)",
		r.Precision*100, r.Recall*100, r.F1*100, r.FalsePositives, r.FalseNegatives, r.TruePositives, r.TrueNegatives,
		r.Duration, r.SamplesPerSecond,
	)
}

// BuildDetector builds a Detector scoped strictly to the "finding"
// band (detector.BandFinding, the package default — no
// WithMinEmitBand(BandLowConfidence) override like cmd/cerberus/scan.go's
// buildDetector uses for interactive CLI debugging) so this benchmark
// measures the same bar docs/architecture/scoring.md documents as
// "emitted as a Finding", not a looser one. fsys/rulesDir follow
// internal/rules.LoadDir's convention (e.g. os.DirFS(".") + "rules").
// The fingerprint key is ephemeral and process-local — Sample.Expected
// never depends on a stable fingerprint, only on RuleID/Confidence.
func BuildDetector(fsys fs.FS, rulesDir string) (*detector.Detector, error) {
	compiled, err := rules.LoadDir(fsys, rulesDir)
	if err != nil {
		return nil, fmt.Errorf("loading rules from %s: %w", rulesDir, err)
	}
	if len(compiled) == 0 {
		return nil, fmt.Errorf("no rules loaded from %s", rulesDir)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating fingerprint key: %w", err)
	}
	fp, err := policy.NewFingerprinter(key)
	if err != nil {
		return nil, err
	}

	return detector.New(compiled, fp), nil // default minEmitBand: BandFinding
}
