package detector

import (
	"fmt"
	"strings"

	"github.com/HaK0exe/cerberus/internal/rules"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// Score classification bands. See docs/architecture/scoring.md — these
// are starting points to be calibrated against testdata/corpus.
const (
	ThresholdIgnore    = 0.50
	ThresholdLLMReview = 0.70
	ThresholdFinding   = 0.90
)

// Band is the classification a score falls into before any LLM
// validation stage runs.
type Band string

const (
	BandIgnore        Band = "ignore"
	BandLowConfidence Band = "low_confidence"
	BandLLMReview     Band = "llm_review"
	BandFinding       Band = "finding"
)

func Classify(score float64) Band {
	switch {
	case score >= ThresholdFinding:
		return BandFinding
	case score >= ThresholdLLMReview:
		return BandLLMReview
	case score >= ThresholdIgnore:
		return BandLowConfidence
	default:
		return BandIgnore
	}
}

const contextWindow = 200 // bytes of surrounding context inspected for keywords

// contextWindowBounds returns the [start, end) byte range of content
// inspected as "surrounding context" for a match spanning
// [matchStart, matchEnd) — the same ±contextWindow-byte window
// explainScore uses for keyword/negative-keyword matching. Exported
// (within the package) so callers that need the raw context text for
// something other than scoring — e.g. building a
// cerberus.ValidationInput for the optional LLM stage — use the exact
// same window rather than duplicating the bounds logic.
func contextWindowBounds(contentLen, matchStart, matchEnd int) (int, int) {
	return max(0, matchStart-contextWindow), min(contentLen, matchEnd+contextWindow)
}

// explainScore computes an explainable confidence score for a
// candidate match of rule against content: every term that contributed
// is captured as a cerberus.Signal, so DeterministicScore is never an
// opaque float — it is always sum(Signals), clamped to [0, 1]. Callers
// that only need the number can read ds.FinalScore; callers building
// DetectionProvenance keep ds.Signals for `cerberus scan file --format
// explain`.
//
// No LLM runs here — LLMAdjustment stays 0 and FinalScore ==
// DeterministicScore. A Validator stage (internal/llm) composes on top
// of this and sets LLMAdjustment separately; see docs/adr/0002.
func explainScore(rule rules.CompiledRule, content []byte, start, end int) cerberus.DetectionScore {
	var signals []cerberus.Signal

	signals = append(signals, cerberus.Signal{
		Name:   "rule_base_confidence",
		Score:  rule.Confidence,
		Reason: fmt.Sprintf("declared base confidence for rule %q", rule.ID),
	})

	ctxStart, ctxEnd := contextWindowBounds(len(content), start, end)
	contextStr := strings.ToLower(string(content[ctxStart:ctxEnd]))

	if rule.Entropy.Enabled {
		value := content[start:end]
		e := ShannonEntropy(value)
		if e >= rule.Entropy.Threshold {
			signals = append(signals, cerberus.Signal{
				Name:   "entropy",
				Score:  0.10,
				Reason: fmt.Sprintf("entropy %.2f >= threshold %.2f", e, rule.Entropy.Threshold),
			})
		} else {
			signals = append(signals, cerberus.Signal{
				Name:   "entropy",
				Score:  -0.15,
				Reason: fmt.Sprintf("entropy %.2f < threshold %.2f", e, rule.Entropy.Threshold),
			})
		}
	}

	if kw, ok := matchedKeyword(contextStr, rule.Keywords); ok {
		signals = append(signals, cerberus.Signal{
			Name:   "keyword_context",
			Score:  0.10,
			Reason: fmt.Sprintf("keyword %q found within %dB of the match", kw, contextWindow),
		})
	} else if len(rule.Keywords) > 0 {
		signals = append(signals, cerberus.Signal{
			Name:   "keyword_context",
			Score:  0,
			Reason: "no configured keyword found in surrounding context",
		})
	}

	if kw, ok := matchedKeyword(contextStr, rule.NegativeKeywords); ok {
		signals = append(signals, cerberus.Signal{
			Name:   "negative_keyword",
			Score:  -0.40,
			Reason: fmt.Sprintf("negative keyword %q found within %dB of the match", kw, contextWindow),
		})
	} else if len(rule.NegativeKeywords) > 0 {
		signals = append(signals, cerberus.Signal{
			Name:   "negative_keyword",
			Score:  0,
			Reason: "no negative keyword found in surrounding context",
		})
	}

	var sum float64
	for _, sig := range signals {
		sum += sig.Score
	}
	deterministic := clamp01(sum)

	return cerberus.DetectionScore{
		Signals:            signals,
		DeterministicScore: deterministic,
		LLMAdjustment:      0,
		FinalScore:         deterministic,
	}
}

func matchedKeyword(context string, keywords []string) (string, bool) {
	for _, kw := range keywords {
		if strings.Contains(context, strings.ToLower(kw)) {
			return kw, true
		}
	}
	return "", false
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
