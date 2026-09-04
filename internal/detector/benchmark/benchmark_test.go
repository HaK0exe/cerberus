package benchmark

import (
	"context"
	"math"
	"testing"
	"testing/fstest"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func almostEqual(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// TestCompute_KnownConfusion locks down the precision/recall/F1 math
// against a hand-computed confusion matrix, independent of any
// detector or corpus — this is the thing the issue's acceptance
// criteria actually needs proven correct.
func TestCompute_KnownConfusion(t *testing.T) {
	tests := []struct {
		name                 string
		c                    Confusion
		wantP, wantR, wantF1 float64
	}{
		{
			name:  "perfect classifier",
			c:     Confusion{TruePositives: 10, FalseNegatives: 0, FalsePositives: 0, TrueNegatives: 10},
			wantP: 1.0, wantR: 1.0, wantF1: 1.0,
		},
		{
			name: "textbook 8/2/3/7 example",
			// 8 TP, 2 FN (10 actual positives), 3 FP, 7 TN.
			// precision = 8/11 = 0.7272..., recall = 8/10 = 0.8,
			// F1 = 2*P*R/(P+R) = 2*0.727273*0.8/(1.527273) = 0.761905
			c:     Confusion{TruePositives: 8, FalseNegatives: 2, FalsePositives: 3, TrueNegatives: 7},
			wantP: 8.0 / 11.0, wantR: 0.8, wantF1: 0.7619047619047619,
		},
		{
			name:  "nothing flagged at all",
			c:     Confusion{TruePositives: 0, FalseNegatives: 5, FalsePositives: 0, TrueNegatives: 5},
			wantP: 0, wantR: 0, wantF1: 0,
		},
		{
			name:  "no true positives in corpus",
			c:     Confusion{TruePositives: 0, FalseNegatives: 0, FalsePositives: 2, TrueNegatives: 8},
			wantP: 0, wantR: 0, wantF1: 0,
		},
		{
			name:  "over-flagging everything",
			c:     Confusion{TruePositives: 5, FalseNegatives: 0, FalsePositives: 5, TrueNegatives: 0},
			wantP: 0.5, wantR: 1.0, wantF1: 2.0 / 3.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := Compute(tt.c)
			if !almostEqual(m.Precision, tt.wantP) {
				t.Errorf("precision = %v, want %v", m.Precision, tt.wantP)
			}
			if !almostEqual(m.Recall, tt.wantR) {
				t.Errorf("recall = %v, want %v", m.Recall, tt.wantR)
			}
			if !almostEqual(m.F1, tt.wantF1) {
				t.Errorf("F1 = %v, want %v", m.F1, tt.wantF1)
			}
			if got := tt.c.Total(); got != tt.c.TruePositives+tt.c.FalseNegatives+tt.c.FalsePositives+tt.c.TrueNegatives {
				t.Errorf("Total() = %d, inconsistent with fields", got)
			}
		})
	}
}

// stubDetector emits a canned Finding for any artifact whose path is
// in flag, and nothing otherwise — enough to drive Run() through all
// four confusion-matrix outcomes without depending on the real
// detector package.
type stubDetector struct {
	flag map[string]bool
}

func (s stubDetector) Detect(_ context.Context, a cerberus.Artifact) ([]cerberus.Finding, error) {
	if s.flag[a.Path] {
		return []cerberus.Finding{{ID: "fnd_stub", Path: a.Path}}, nil
	}
	return nil, nil
}

// TestRun_ConfusionMatrix builds a tiny synthetic corpus with a known
// ground truth and a stub detector with a known (and deliberately
// imperfect) flagging behavior, and checks Run() derives exactly the
// confusion matrix that behavior implies.
func TestRun_ConfusionMatrix(t *testing.T) {
	samples := []Sample{
		{Path: "true_positive/a", Label: TruePositive, Artifact: cerberus.Artifact{Path: "true_positive/a"}},    // flagged -> TP
		{Path: "true_positive/b", Label: TruePositive, Artifact: cerberus.Artifact{Path: "true_positive/b"}},    // not flagged -> FN
		{Path: "false_positive/c", Label: FalsePositive, Artifact: cerberus.Artifact{Path: "false_positive/c"}}, // flagged -> FP
		{Path: "false_positive/d", Label: FalsePositive, Artifact: cerberus.Artifact{Path: "false_positive/d"}}, // not flagged -> TN
	}

	det := stubDetector{flag: map[string]bool{
		"true_positive/a":  true,
		"false_positive/c": true,
	}}

	res, err := Run(context.Background(), det, samples)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	want := Confusion{TruePositives: 1, FalseNegatives: 1, FalsePositives: 1, TrueNegatives: 1}
	if res.Metrics.Confusion != want {
		t.Fatalf("confusion = %+v, want %+v", res.Metrics.Confusion, want)
	}
	if len(res.Samples) != 4 {
		t.Fatalf("len(res.Samples) = %d, want 4", len(res.Samples))
	}

	outcomes := map[string]string{}
	for _, sr := range res.Samples {
		outcomes[sr.Sample.Path] = sr.Outcome()
	}
	wantOutcomes := map[string]string{
		"true_positive/a":  "tp",
		"true_positive/b":  "fn",
		"false_positive/c": "fp",
		"false_positive/d": "tn",
	}
	for path, want := range wantOutcomes {
		if got := outcomes[path]; got != want {
			t.Errorf("outcome[%s] = %q, want %q", path, got, want)
		}
	}
}

func TestRun_NilDetector(t *testing.T) {
	if _, err := Run(context.Background(), nil, nil); err == nil {
		t.Fatal("expected error for nil detector, got nil")
	}
}

// TestLoadCorpus_SyntheticLayout exercises LoadCorpus against an
// in-memory fstest.MapFS rather than the real testdata/corpus, so this
// test's expectations don't drift if the real corpus grows or shrinks.
func TestLoadCorpus_SyntheticLayout(t *testing.T) {
	fsys := fstest.MapFS{
		"corpus/true_positive/one.env":    &fstest.MapFile{Data: []byte("secret=abc")},
		"corpus/true_positive/two.env":    &fstest.MapFile{Data: []byte("secret=def")},
		"corpus/false_positive/three.env": &fstest.MapFile{Data: []byte("not a secret")},
		"corpus/false_positive/.hidden":   &fstest.MapFile{Data: []byte("ignored")},
		"corpus/README.md":                &fstest.MapFile{Data: []byte("ignored, not under a label dir")},
	}

	samples, err := LoadCorpus(fsys, "corpus")
	if err != nil {
		t.Fatalf("LoadCorpus: %v", err)
	}
	if len(samples) != 3 {
		t.Fatalf("len(samples) = %d, want 3 (dotfile and top-level README must be excluded)", len(samples))
	}

	var tp, fp int
	for _, s := range samples {
		if s.Label == TruePositive {
			tp++
		} else {
			fp++
		}
		if len(s.Artifact.Content) == 0 {
			t.Errorf("sample %s has empty content", s.Path)
		}
		if s.Artifact.SourceType != cerberus.SourceFile {
			t.Errorf("sample %s SourceType = %v, want SourceFile", s.Path, s.Artifact.SourceType)
		}
	}
	if tp != 2 || fp != 1 {
		t.Errorf("tp=%d fp=%d, want tp=2 fp=1", tp, fp)
	}
}

func TestLoadCorpus_MissingDir(t *testing.T) {
	fsys := fstest.MapFS{}
	if _, err := LoadCorpus(fsys, "nowhere"); err == nil {
		t.Fatal("expected error for missing corpus directory, got nil")
	}
}

// TestRealCorpus_Loads is a smoke test against the actual
// testdata/corpus checked into the repo: it must load, be non-trivial
// in size, and contain both labels. It intentionally does not assert
// exact counts so adding corpus samples (see issue #66) doesn't break
// this test.
func TestRealCorpus_Loads(t *testing.T) {
	samples, err := LoadCorpus(realCorpusFS(t), "testdata/corpus")
	if err != nil {
		t.Fatalf("LoadCorpus(testdata/corpus): %v", err)
	}
	if len(samples) < 10 {
		t.Fatalf("only %d samples loaded from testdata/corpus, expected a non-trivial starter corpus", len(samples))
	}

	var tp, fp int
	for _, s := range samples {
		if s.Label == TruePositive {
			tp++
		} else {
			fp++
		}
	}
	if tp == 0 || fp == 0 {
		t.Fatalf("expected both labels present, got tp=%d fp=%d", tp, fp)
	}
}
