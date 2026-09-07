package benchmark_test

import (
	"context"
	"crypto/rand"
	"os"
	"testing"

	"github.com/HaK0exe/cerberus/internal/detector"
	"github.com/HaK0exe/cerberus/internal/detector/benchmark"
	"github.com/HaK0exe/cerberus/internal/policy"
	"github.com/HaK0exe/cerberus/internal/rules"
)

func TestShippingCLIQualityFloor(t *testing.T) {
	root := os.DirFS("../../..")
	samples, err := benchmark.LoadCorpus(root, "testdata/corpus")
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	compiled, err := rules.LoadDir(root, "rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	fp, err := policy.NewFingerprinter(key)
	if err != nil {
		t.Fatal(err)
	}
	d := detector.New(compiled, fp, detector.WithMinEmitBand(detector.BandLowConfidence))
	result, err := benchmark.Run(context.Background(), d, samples)
	if err != nil {
		t.Fatalf("run benchmark: %v", err)
	}

	if result.Metrics.Precision < 0.90 {
		t.Errorf("shipping CLI precision %.4f is below 0.90", result.Metrics.Precision)
	}
	if result.Metrics.Recall < 0.80 {
		t.Errorf("shipping CLI recall %.4f is below 0.80", result.Metrics.Recall)
	}
}
