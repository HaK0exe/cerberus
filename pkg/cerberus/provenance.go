package cerberus

import "time"

// Signal is one named contribution to a DetectionScore — a single
// interpretable term (rule confidence, entropy, keyword context, ...)
// with the amount it added or subtracted and a human-readable reason.
// Signals are what make a score explainable: `sum(Signals) ==
// DeterministicScore`, not an opaque float.
type Signal struct {
	Name   string
	Score  float64
	Reason string
}

// DetectionScore is the explainable breakdown behind a Finding's
// Confidence. DeterministicScore is the sum of Signals, clamped to
// [0, 1]; LLMAdjustment is the optional local-LLM nudge applied on top
// (zero when no Validator ran or it made no adjustment); FinalScore is
// DeterministicScore+LLMAdjustment, clamped to [0, 1] again.
type DetectionScore struct {
	Signals []Signal

	DeterministicScore float64
	LLMAdjustment      float64

	FinalScore float64
}

// DetectionProvenance records how a Finding's score was produced, so
// an analyst can reconstruct the decision after the fact (`cerberus
// scan file --format explain`, later `cerberus findings explain
// <id>`) without ever needing the raw secret value.
type DetectionProvenance struct {
	DetectorVersion string
	RulesetVersion  string

	RuleID  string
	Signals []Signal

	// LLM fields are left zero-valued when no Validator ran — a
	// Finding produced deterministically must never claim a model
	// reviewed it.
	PromptVersion string
	ModelName     string
	ModelDigest   string

	CreatedAt time.Time
}
