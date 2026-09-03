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

// Finding is the persisted, safe-to-store representation of a detected
// secret. It MUST NOT contain the raw secret value: only fingerprint,
// masked prefix, and metadata needed to locate and triage it.
//
// See docs/adr/0001-no-raw-secret-storage.md for the rationale.
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

	// MaskedPrefix is a human-readable, non-reversible hint such as
	// "AKIA************".
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
}
