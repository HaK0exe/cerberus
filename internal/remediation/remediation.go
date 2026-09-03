// Package remediation defines the provider-agnostic remediation
// contracts: RemediationPlan, its lifecycle states, and the
// Planner/Executor split that keeps detection and remediation
// privileges separate (see docs/architecture/remediation-separation.md).
//
// Provider implementations (internal/remediation/aws, ...) never run in
// the same IAM role/process privileges as scanners.
package remediation

import "time"

// Status is the lifecycle state of a RemediationPlan.
type Status string

const (
	StatusProposed         Status = "PROPOSED"
	StatusApprovalRequired Status = "APPROVAL_REQUIRED"
	StatusApproved         Status = "APPROVED"
	StatusExecuting        Status = "EXECUTING"
	StatusKeyDisabled      Status = "KEY_DISABLED"
	StatusMonitoring       Status = "MONITORING"
	StatusKeyDeleted       Status = "KEY_DELETED"
	StatusFailed           Status = "FAILED"
	StatusCancelled        Status = "CANCELLED"
)

// Target identifies the credential/principal a plan acts on. Fields
// are provider-specific; AWS populates AccountID/Principal/KeyFingerprint.
type Target struct {
	Provider       string
	AccountID      string
	Principal      string
	KeyFingerprint string
}

// Plan is a proposed remediation action awaiting approval and
// execution. It is never auto-approved: ApprovalRequired defaults to
// true and DryRun defaults to true (see docs/security/remediation.md).
type Plan struct {
	ID        string
	FindingID string
	Provider  string
	Action    string
	Target    Target

	ApprovalRequired bool
	DryRun           bool

	Status Status

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Planner builds a Plan from a Finding without executing anything.
// Planners hold read-only credentials at most (e.g. to resolve which
// AWS account/identity a key belongs to).
type Planner interface {
	Plan(findingID string) (Plan, error)
}

// Executor carries out an APPROVED Plan. Executors are the only
// component allowed to hold write credentials (e.g. iam:UpdateAccessKey),
// and must refuse to execute a Plan that is not in StatusApproved.
type Executor interface {
	Execute(plan Plan) (Plan, error)
}
