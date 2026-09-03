# Scoring

`internal/detector.score` computes a deterministic confidence score in
`[0, 1]` for each rule match, starting from the rule's declared base
`confidence` and adjusting for entropy and context:

```text
base                              rule.Confidence
entropy compatible                +0.10
entropy incompatible (if enabled) -0.15
keyword found nearby              +0.10
negative keyword found nearby     -0.40
```

Context is inspected within a ±200-byte window around the match
(`contextWindow` in `internal/detector/scoring.go`).

## Classification bands

```go
const (
	ThresholdIgnore    = 0.50
	ThresholdLLMReview = 0.70
	ThresholdFinding   = 0.90
)
```

| Score range | Band | Behavior |
|---|---|---|
| `< 0.50` | `ignore` | dropped |
| `[0.50, 0.70)` | `low_confidence` | dropped by default; emitted with `WithMinEmitBand(BandLowConfidence)` for debugging/rule-testing |
| `[0.70, 0.90)` | `llm_review` | routed to the local LLM validator when enabled (Sprint 3); otherwise dropped |
| `≥ 0.90` | `finding` | emitted as a `Finding` |

**These thresholds are starting points, not fixed constants.** They
must be calibrated against `testdata/corpus` (target: 5,000 synthetic
true positives, 10,000 realistic false positives — see
[`../development/corpus.md`](../development/corpus.md)) before Sprint
1 is considered tuned, and re-validated whenever the rule set changes
materially.

## Adding a new scoring signal

New signals (e.g. "sensitive file extension", "sensitive variable
name") should be added as additional weighted terms in
`internal/detector/scoring.go`'s `score` function, each with:

- a one-line rationale for the weight chosen;
- at least one corpus sample demonstrating it helps (not just intuition);
- a note in this document.

Avoid stacking many small heuristics without corpus evidence — false
positive reduction here is only worth as much as the corpus that
validates it.
