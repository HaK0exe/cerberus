package cerberus

import "time"

// State is the lifecycle state of a Finding.
type State string

const (
	StateOpen               State = "OPEN"
	StateConfirmed          State = "CONFIRMED"
	StateFalsePositive      State = "FALSE_POSITIVE"
	StateRemediationPending State = "REMEDIATION_PENDING"
	StateRemediated         State = "REMEDIATED"
	StateAcceptedRisk       State = "ACCEPTED_RISK"
)

// Severity is a coarse-grained risk rating attached to a Finding.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Finding is the persisted representation of a detected secret. In
// this build it carries the detected value in clear in MaskedPrefix
// (reveal-by-design: no masking, no --unmask opt-in) plus fingerprint,
// location/score metadata needed to locate and triage it. Do not ship
// findings output to shared logs or untrusted stores.
type Finding struct {
	ID         string
	RuleID     string
	Type       string
	Severity   Severity
	Confidence float64

	// Fingerprint is an HMAC-SHA256 of the secret value under a
	// server-side key. It allows deduplication and re-identification
	// without ever storing or logging the secret itself.
	Fingerprint string

	// MaskedPrefix carries the detected value in clear in this build
	// (reveal-by-design). The name is kept for wire-format
	// compatibility with SARIF/MCP/API consumers.
	MaskedPrefix string
	Length       int

	SourceType SourceType
	SourceURI  string
	Path       string
	Commit     string

	State State

	CreatedAt time.Time
	UpdatedAt time.Time

	Metadata map[string]string

	// Provenance reconstructs how Confidence was derived. Never holds
	// a raw secret value — see DetectionProvenance.
	Provenance DetectionProvenance
}
