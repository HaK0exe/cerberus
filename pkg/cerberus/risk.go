package cerberus

// RiskLevel is a coarse, human-facing bucket for a RiskAssessment.Score.
// Unlike Finding.Severity (which reflects how bad the credential *type*
// is in the abstract, e.g. "a private key is always high"), RiskLevel
// reflects how bad *this specific exposure* is right now — see
// docs/adr/0005-risk-engine.md for why the two are kept separate.
type RiskLevel string

const (
	RiskInfo     RiskLevel = "INFO"
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

// RiskFactor is one named, explainable multiplicative contribution to a
// RiskAssessment.Score — the risk-engine analogue of Signal, which
// covers additive detection-confidence terms instead. A Multiplier of
// 1.0 means "this factor did not move the score"; every RiskFactor
// present in an assessment must carry a non-empty Reason so the
// assessment can be reconstructed by an analyst without re-running the
// engine.
type RiskFactor struct {
	Name       string
	Multiplier float64
	Reason     string
}

// RiskAssessment is the explainable output of the risk engine for a
// single Credential: a bounded, documented Score, the RiskLevel it maps
// to, and the ordered list of Factors whose product produced it. It
// never carries a raw secret value.
type RiskAssessment struct {
	Score float64
	Level RiskLevel

	Factors []RiskFactor
}
