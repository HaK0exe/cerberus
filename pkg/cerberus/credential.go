package cerberus

import "time"

// CredentialStatus is the lifecycle status of a Credential.
type CredentialStatus string

const (
	CredentialStatusActive     CredentialStatus = "ACTIVE"
	CredentialStatusRemediated CredentialStatus = "REMEDIATED"
	CredentialStatusRevoked    CredentialStatus = "REVOKED"
	CredentialStatusIgnored    CredentialStatus = "IGNORED"
)

// Credential is the logical identity of a single secret value, derived
// from its HMAC fingerprint. Every Finding that shares a Fingerprint
// correlates to the same Credential regardless of how many times or
// where it was observed — see internal/credentials for the correlation
// service that builds these from Findings.
//
// Like Finding, a Credential never holds a raw secret value, and its
// Fingerprint must never be treated as an authenticatable substitute
// for the secret it identifies.
type Credential struct {
	ID string

	Fingerprint string

	Provider string
	Kind     string

	FirstSeen time.Time
	LastSeen  time.Time

	ExposureCount int

	Status CredentialStatus
}

// Exposure is a single location where a Credential was observed. A
// Credential with Exposures at more than one SourceURI/Path/Commit has
// been duplicated or reused across locations.
type Exposure struct {
	ID           string
	CredentialID string

	SourceType SourceType
	SourceURI  string
	Path       string
	Commit     string

	FirstSeen time.Time
	LastSeen  time.Time

	// Visibility is a coarse reachability classification for this
	// location (e.g. "public", "private"). Left empty when unknown —
	// populated by scanner/enrichment context, never guessed.
	Visibility string
}

// IncidentStatus is the lifecycle status of an Incident.
type IncidentStatus string

const (
	IncidentStatusOpen       IncidentStatus = "OPEN"
	IncidentStatusInProgress IncidentStatus = "IN_PROGRESS"
	IncidentStatusResolved   IncidentStatus = "RESOLVED"
	IncidentStatusIgnored    IncidentStatus = "IGNORED"
)

// Incident groups the Exposures of a single Credential for triage,
// risk scoring, and remediation. The current correlation service keeps
// a 1:1 Incident<->Credential mapping; nothing here prevents a future
// policy from merging incidents across related credentials.
type Incident struct {
	ID           string
	CredentialID string

	ExposureIDs []string

	RiskScore float64

	Status IncidentStatus

	CreatedAt time.Time
	UpdatedAt time.Time
}
