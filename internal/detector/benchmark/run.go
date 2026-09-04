package benchmark

import (
	"context"
	"fmt"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// SampleResult is the per-sample outcome of running a Detect against
// one labeled corpus Sample.
type SampleResult struct {
	Sample   Sample
	Findings []cerberus.Finding
	Err      error
}

// Flagged reports whether the detector emitted at least one Finding
// for this sample.
func (r SampleResult) Flagged() bool { return len(r.Findings) > 0 }

// Outcome classifies this result against the sample's ground-truth
// Label: "tp", "fn", "fp", or "tn".
func (r SampleResult) Outcome() string {
	switch {
	case r.Sample.Label == TruePositive && r.Flagged():
		return "tp"
	case r.Sample.Label == TruePositive && !r.Flagged():
		return "fn"
	case r.Sample.Label == FalsePositive && r.Flagged():
		return "fp"
	default:
		return "tn"
	}
}

// Result is a full benchmark run: metrics plus every per-sample
// outcome, so a caller (a report generator, a CLI, a test) can explain
// exactly which samples drove the numbers.
type Result struct {
	Metrics Metrics
	Samples []SampleResult
}

// detector is the minimal surface run() needs — satisfied by
// *detector.Detector (both the LLM-free baseline and one built with
// detector.WithValidator wired in to a real or fake cerberus.Validator).
// Kept as a narrow local interface rather than importing
// internal/detector's concrete type, so this package never needs to
// change alongside a detector.Detector refactor.
type Detector interface {
	Detect(ctx context.Context, artifact cerberus.Artifact) ([]cerberus.Finding, error)
}

// Run executes det.Detect against every sample and computes precision/
// recall/F1 over the results. A per-sample Detect error is recorded on
// that SampleResult (and treated as "not flagged" for the confusion
// matrix — a detector that errors out found nothing) rather than
// aborting the whole run, so one bad sample doesn't hide the rest of
// the benchmark.
func Run(ctx context.Context, det Detector, samples []Sample) (Result, error) {
	if det == nil {
		return Result{}, fmt.Errorf("benchmark.Run: det is nil")
	}

	var res Result
	var c Confusion

	for _, s := range samples {
		findings, err := det.Detect(ctx, s.Artifact)
		sr := SampleResult{Sample: s, Findings: findings, Err: err}
		res.Samples = append(res.Samples, sr)

		switch sr.Outcome() {
		case "tp":
			c.TruePositives++
		case "fn":
			c.FalseNegatives++
		case "fp":
			c.FalsePositives++
		case "tn":
			c.TrueNegatives++
		}
	}

	res.Metrics = Compute(c)
	return res, nil
}
