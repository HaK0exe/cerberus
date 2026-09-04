// Package remediation defines the provider-agnostic remediation
// contracts: RemediationPlan, its lifecycle states, and the
// Planner/Executor split that keeps detection and remediation
// privileges separate (see docs/adr/0003-remediation-separation.md).
//
// Provider implementations (internal/remediation/aws, ...) never run in
// the same IAM role/process privileges as scanners. This package must
// never import internal/detector or internal/scanner/... — it acts on
// a cerberus.Credential and its Exposures, handed to it by the control
// plane, never by re-scanning anything itself (enforced by
// internal/architecture's boundary test).
package remediation

import (
	"context"
	"time"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// Status is the lifecycle state of a Plan. See CanTransition for the
// legal state machine — nothing in this package mutates Status outside
// of that table, so an illegal jump (e.g. Executing a Proposed plan
// without going through Approved) is always a caught, explained error,
// never a silent bug.
type Status string

const (
	// StatusProposed is a freshly built Plan: risk has been assessed
	// and policy evaluated, but no approval decision has been recorded
	// yet. Equivalent to the spec's "Draft".
	StatusProposed Status = "PROPOSED"
	// StatusApprovalRequired is a Plan whose policy decision requires
	// one or more approvals that have not yet been granted.
	// Equivalent to the spec's "PendingApproval".
	StatusApprovalRequired Status = "APPROVAL_REQUIRED"
	StatusApproved         Status = "APPROVED"
	StatusExecuting        Status = "EXECUTING"
	// StatusKeyDisabled is the spec's "Executed" — the disable action
	// itself succeeded, but re-verification hasn't confirmed it yet.
	StatusKeyDisabled Status = "KEY_DISABLED"
	// StatusMonitoring is reserved for a future asynchronous
	// verification window (e.g. "check again in N minutes"); today's
	// Executor verifies synchronously right after disabling, so this
	// state is defined but not yet reachable — see docs/adr/0010.
	StatusMonitoring Status = "MONITORING"
	// StatusVerified is a re-confirmed disable: the Executor re-read
	// the credential's live status after disabling and it matches.
	// Terminal success state.
	StatusVerified Status = "VERIFIED"
	// StatusKeyDeleted is reserved for the "optional later deletion"
	// step the spec explicitly defers — no code path in this package
	// produces it yet.
	StatusKeyDeleted Status = "KEY_DELETED"
	StatusFailed     Status = "FAILED"
	StatusCancelled  Status = "CANCELLED"
)

// Target identifies the credential/principal a plan acts on. Fields
// are provider-specific; AWS populates AccountID/Principal/KeyFingerprint.
// Target never carries the raw secret value — only what's needed to
// locate the credential at the provider (e.g. an AWS access key ID is
// not itself secret; the corresponding secret access key is, and never
// appears here).
type Target struct {
	Provider       string
	AccountID      string
	Principal      string
	KeyFingerprint string
}

// Plan is a proposed remediation action awaiting approval and
// execution. Building a Plan (see Planner) MUST NOT have any side
// effect outside the process — no API call that changes provider
// state. It is never auto-approved: ApprovalRequired/ApprovalsRequired
// come from a PolicyDecision, and DryRun defaults to true (see
// docs/security/remediation.md).
type Plan struct {
	ID string

	// CredentialID is the primary key a Plan targets — one Plan per
	// Credential (the deduplicated identity from internal/credentials),
	// not per individual Finding occurrence. FindingID is kept for
	// backward audit-trail linkage to the specific detection that
	// triggered planning and may be empty when a Plan is built purely
	// from a correlated Credential.
	CredentialID string
	FindingID    string

	Provider string
	Action   string
	Target   Target

	// Risk is the RiskAssessment (internal/risk.Assess) this Plan is
	// responding to — a Plan without a Risk is never produced by
	// DefaultPlanner.
	Risk cerberus.RiskAssessment

	ApprovalRequired  bool
	ApprovalsRequired int
	ApprovalsGranted  int
	DryRun            bool

	Status Status
	// Reason explains the current Status — never empty once a Plan has
	// left the zero value, matching the Reason-is-never-empty
	// convention used throughout this codebase (cerberus.Signal,
	// cerberus.RiskFactor, policyengine.PolicyDecision).
	Reason string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Planner builds a Plan from a Credential and its Exposures without
// executing anything. Planners hold read-only credentials at most
// (e.g. to resolve which AWS account/identity a key belongs to) — see
// docs/adr/0003-remediation-separation.md.
type Planner interface {
	// environment feeds PolicyInput.Environment (e.g. "production",
	// "development") — the remediation policy schema
	// (policyengine.RemediationRule) is keyed on provider+environment,
	// so a Planner that ignored this would never match any
	// environment-scoped rule.
	Plan(ctx context.Context, credential cerberus.Credential, exposures []cerberus.Exposure, action, environment string) (Plan, error)
}

// Executor carries out a Plan. Executors are the only component
// allowed to hold write credentials (e.g. iam:UpdateAccessKey), and
// must refuse to act on a Plan that is not Approved (or, for the
// idempotent retry/verification path, already KeyDisabled/Failed from
// a prior Execute call — see CanTransition and each provider's
// Executor for the exact gate).
//
// An Executor implementation must never use the discovered
// credential's own value to authenticate its provider calls — it acts
// using Cerberus's own, separately-provisioned identity. Nothing in
// cerberus.Credential/Finding carries a raw secret value to begin with
// (see docs/adr/0001-no-raw-secret-storage.md), so there is nothing
// for an Executor to (mis)use even by accident — this comment records
// the invariant explicitly because it is the single most
// safety-critical property of this package.
type Executor interface {
	Execute(ctx context.Context, plan Plan) (Plan, error)
}
