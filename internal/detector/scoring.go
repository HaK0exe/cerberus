package detector

import (
	"strings"

	"github.com/HaK0exe/cerberus/internal/rules"
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
// [matchStart, matchEnd) — the same ±contextWindow-byte window score
// uses for keyword/negative-keyword matching. Exported (within the
// package) so callers that need the raw context text for something
// other than scoring — e.g. building a cerberus.ValidationInput for
// the optional LLM stage — use the exact same window rather than
// duplicating the bounds logic.
func contextWindowBounds(contentLen, matchStart, matchEnd int) (int, int) {
	return max(0, matchStart-contextWindow), min(contentLen, matchEnd+contextWindow)
}

// score computes a deterministic confidence score in [0, 1] for a
// candidate match of rule against content, using surrounding context.
func score(rule rules.CompiledRule, content []byte, start, end int) float64 {
	s := rule.Confidence

	ctxStart, ctxEnd := contextWindowBounds(len(content), start, end)
	context := strings.ToLower(string(content[ctxStart:ctxEnd]))

	if rule.Entropy.Enabled {
		value := content[start:end]
		if ShannonEntropy(value) >= rule.Entropy.Threshold {
			s += 0.10
		} else {
			s -= 0.15
		}
	}

	for _, kw := range rule.Keywords {
		if strings.Contains(context, strings.ToLower(kw)) {
			s += 0.10
			break
		}
	}

	for _, kw := range rule.NegativeKeywords {
		if strings.Contains(context, strings.ToLower(kw)) {
			s -= 0.40
			break
		}
	}

	if s < 0 {
		s = 0
	}
	if s > 1 {
		s = 1
	}
	return s
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
