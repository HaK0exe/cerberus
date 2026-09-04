package detector

import (
	"regexp"
	"testing"

	"github.com/HaK0exe/cerberus/internal/rules"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func buildRule(t *testing.T, r cerberus.Rule) rules.CompiledRule {
	t.Helper()
	return rules.CompiledRule{Rule: r, Pattern: regexp.MustCompile(r.Regex)}
}

func TestExplainScore_SignalsSumToDeterministicScore(t *testing.T) {
	rule := buildRule(t, cerberus.Rule{
		ID:         "test-rule",
		Regex:      `SECRETVALUE1234567890ABCDEF`,
		Confidence: 0.60,
		Keywords:   []string{"api_key"},
		Entropy:    cerberus.EntropyConfig{Enabled: true, Threshold: 3.0},
	})

	content := []byte("api_key = SECRETVALUE1234567890ABCDEF")
	start := len("api_key = ")
	end := start + len("SECRETVALUE1234567890ABCDEF")

	ds := explainScore(rule, content, start, end)

	var sum float64
	for _, s := range ds.Signals {
		sum += s.Score
	}
	if sum != ds.DeterministicScore {
		t.Errorf("signals sum to %.4f but DeterministicScore is %.4f", sum, ds.DeterministicScore)
	}
	if ds.LLMAdjustment != 0 {
		t.Errorf("no LLM ran, LLMAdjustment should be 0, got %.4f", ds.LLMAdjustment)
	}
	if ds.FinalScore != ds.DeterministicScore {
		t.Errorf("with no LLM adjustment, FinalScore should equal DeterministicScore: %.4f vs %.4f", ds.FinalScore, ds.DeterministicScore)
	}

	names := map[string]bool{}
	for _, s := range ds.Signals {
		names[s.Name] = true
		if s.Reason == "" {
			t.Errorf("signal %q has no reason", s.Name)
		}
	}
	for _, want := range []string{"rule_base_confidence", "entropy", "keyword_context"} {
		if !names[want] {
			t.Errorf("expected a %q signal, got %+v", want, ds.Signals)
		}
	}
}

func TestExplainScore_NegativeKeywordSuppressesScore(t *testing.T) {
	rule := buildRule(t, cerberus.Rule{
		ID:               "test-rule",
		Regex:            `SECRETVALUE1234567890ABCDEF`,
		Confidence:       0.90,
		NegativeKeywords: []string{"example"},
	})

	content := []byte("example: SECRETVALUE1234567890ABCDEF")
	start := len("example: ")
	end := start + len("SECRETVALUE1234567890ABCDEF")

	ds := explainScore(rule, content, start, end)

	found := false
	for _, s := range ds.Signals {
		if s.Name == "negative_keyword" {
			found = true
			if s.Score >= 0 {
				t.Errorf("negative_keyword signal should be negative, got %.4f", s.Score)
			}
		}
	}
	if !found {
		t.Fatal("expected a negative_keyword signal")
	}
	if ds.FinalScore >= ThresholdFinding {
		t.Errorf("negative keyword should have suppressed the score below finding threshold, got %.4f", ds.FinalScore)
	}
}

func TestExplainScore_ClampsToUnitInterval(t *testing.T) {
	rule := buildRule(t, cerberus.Rule{
		ID:         "test-rule",
		Regex:      `X{1,}`,
		Confidence: 1.5, // deliberately out of range
	})

	ds := explainScore(rule, []byte("XXXX"), 0, 4)
	if ds.FinalScore > 1 || ds.FinalScore < 0 {
		t.Errorf("FinalScore must be clamped to [0,1], got %.4f", ds.FinalScore)
	}
}
