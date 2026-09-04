// Package aws implements the AWS remediation provider: an Executor
// that disables (never deletes, in this slice) a compromised IAM
// access key, scoped to an explicit authorized-account allowlist and
// verified after the fact.
//
// No AWS SDK dependency is used here. IAMClient is this package's own
// minimal seam onto exactly the two calls the disable-and-verify
// workflow needs; a future slice wires github.com/aws/aws-sdk-go-v2's
// IAM client behind this same interface with no other code changes —
// see docs/adr/0010-remediation-v2.md. Every test in this package uses
// an in-memory fake IAMClient: no code path here can reach a real AWS
// account.
package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/HaK0exe/cerberus/internal/remediation"
)

func now() time.Time { return time.Now().UTC() }

// KeyStatus mirrors AWS IAM's access key Status values.
type KeyStatus string

const (
	KeyStatusActive   KeyStatus = "Active"
	KeyStatusInactive KeyStatus = "Inactive"
)

// IAMClient is the minimal set of AWS IAM calls this workflow needs.
// Implementations authenticate as Cerberus's own dedicated remediation
// identity — never using anything derived from the discovered
// credential itself (see remediation.Executor's doc comment).
type IAMClient struct {
	// UpdateAccessKey sets accessKeyID's status. The only status this
	// package ever requests is KeyStatusInactive — see Executor.Execute.
	UpdateAccessKey func(ctx context.Context, accountID, accessKeyID string, status KeyStatus) error
	// GetAccessKeyStatus reads accessKeyID's current live status, used
	// to verify a disable actually took effect.
	GetAccessKeyStatus func(ctx context.Context, accountID, accessKeyID string) (KeyStatus, error)
}

// Executor implements remediation.Executor for AWS IAM access keys.
// It performs exactly one privileged action — disabling a key — never
// deletion (the spec's disable-before-delete priority; deletion is
// explicitly deferred, see docs/adr/0010-remediation-v2.md).
type Executor struct {
	client IAMClient

	// authorizedAccountIDs is the allowlist of AWS account IDs this
	// Executor may act against. A Plan whose Target.AccountID is not
	// in this set is rejected before any IAMClient call — the
	// "verify account belongs to authorized organization/scope" step
	// from the spec's AWS workflow.
	authorizedAccountIDs map[string]bool
}

// NewExecutor builds an Executor scoped to authorizedAccountIDs. An
// empty allowlist means no account is authorized — an Executor with no
// configured scope must refuse everything, not default-allow.
func NewExecutor(client IAMClient, authorizedAccountIDs []string) *Executor {
	scope := make(map[string]bool, len(authorizedAccountIDs))
	for _, id := range authorizedAccountIDs {
		scope[id] = true
	}
	return &Executor{client: client, authorizedAccountIDs: scope}
}

var _ remediation.Executor = (*Executor)(nil)

// Execute disables plan's target access key and verifies the disable
// took effect. See the package doc comment for the safety properties
// this implements:
//
//   - Idempotent: a Plan already StatusVerified is returned unchanged,
//     with zero IAMClient calls. A Plan already StatusKeyDisabled only
//     re-attempts verification (never re-calls UpdateAccessKey).
//   - Retry-safe: a Plan that previously landed in StatusFailed can be
//     retried by calling Execute again; a transient UpdateAccessKey
//     error never silently marks the plan disabled.
//   - Scope-restricted: plan.Target.AccountID is checked against the
//     authorized allowlist before any IAMClient call, on every path
//     that would otherwise call UpdateAccessKey.
func (e *Executor) Execute(ctx context.Context, plan remediation.Plan) (remediation.Plan, error) {
	switch plan.Status {
	case remediation.StatusVerified:
		return plan, nil // idempotent no-op: already fully verified

	case remediation.StatusApproved, remediation.StatusFailed:
		return e.disableAndVerify(ctx, plan)

	case remediation.StatusKeyDisabled:
		return e.verifyOnly(ctx, plan)

	default:
		plan.Reason = fmt.Sprintf("aws executor: cannot execute plan in status %s (must be Approved)", plan.Status)
		return plan, fmt.Errorf("%s", plan.Reason)
	}
}

// disableAndVerify runs the full Approved/Failed(retry) -> KeyDisabled
// -> Verified path, starting with the mandatory scope check.
func (e *Executor) disableAndVerify(ctx context.Context, plan remediation.Plan) (remediation.Plan, error) {
	if !e.authorizedAccountIDs[plan.Target.AccountID] {
		plan.Reason = fmt.Sprintf("aws executor: account %q is not in the authorized remediation scope", plan.Target.AccountID)
		return plan, fmt.Errorf("%s", plan.Reason)
	}

	plan.Status = remediation.StatusExecuting
	plan.UpdatedAt = now()

	if err := e.client.UpdateAccessKey(ctx, plan.Target.AccountID, plan.Target.KeyFingerprint, KeyStatusInactive); err != nil {
		plan.Status = remediation.StatusFailed
		plan.Reason = fmt.Sprintf("aws executor: UpdateAccessKey failed: %v", err)
		plan.UpdatedAt = now()
		return plan, err
	}

	plan.Status = remediation.StatusKeyDisabled
	plan.Reason = "aws executor: UpdateAccessKey(Inactive) succeeded, pending verification"
	plan.UpdatedAt = now()

	return e.verifyOnly(ctx, plan)
}

// verifyOnly re-reads the live key status and promotes plan to
// StatusVerified only on a confirmed match. It never calls
// UpdateAccessKey — safe to call repeatedly on a KeyDisabled plan.
func (e *Executor) verifyOnly(ctx context.Context, plan remediation.Plan) (remediation.Plan, error) {
	status, err := e.client.GetAccessKeyStatus(ctx, plan.Target.AccountID, plan.Target.KeyFingerprint)
	if err != nil {
		plan.Reason = fmt.Sprintf("aws executor: verification read failed, retry later: %v", err)
		plan.UpdatedAt = now()
		return plan, nil // stays KeyDisabled: verification failure is not execution failure
	}

	if status != KeyStatusInactive {
		plan.Reason = fmt.Sprintf("aws executor: verification mismatch, live status is %q (expected Inactive), retry later", status)
		plan.UpdatedAt = now()
		return plan, nil // stays KeyDisabled
	}

	plan.Status = remediation.StatusVerified
	plan.Reason = "aws executor: verified key is Inactive"
	plan.UpdatedAt = now()
	return plan, nil
}
