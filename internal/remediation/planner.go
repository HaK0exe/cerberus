package remediation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/HaK0exe/cerberus/internal/policyengine"
	"github.com/HaK0exe/cerberus/internal/risk"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// RiskAssessor matches internal/risk.Assess's signature. Exposed as an
// interface field (defaulting to risk.Assess) purely so tests can
// inject a fixed RiskAssessment without depending on risk's specific
// factor formulas — internal/risk itself stays the real, pure
// implementation DefaultPlanner uses in production.
type RiskAssessor func(cerberus.Credential, []cerberus.Exposure) cerberus.RiskAssessment

// DefaultPlanner implements Planner. It is side-effect-free: Plan only
// reads from the RiskAssessor and PolicyEngine it's given, and never
// calls a provider API — see docs/adr/0010-remediation-v2.md.
type DefaultPlanner struct {
	policy policyengine.PolicyEngine
	assess RiskAssessor
}

// NewPlanner builds a DefaultPlanner backed by the given PolicyEngine.
// Risk assessment defaults to internal/risk.Assess.
func NewPlanner(policy policyengine.PolicyEngine) *DefaultPlanner {
	return &DefaultPlanner{policy: policy, assess: risk.Assess}
}

// WithRiskAssessor overrides the RiskAssessor (tests only, in
// production risk.Assess is always correct to use).
func (p *DefaultPlanner) WithRiskAssessor(a RiskAssessor) *DefaultPlanner {
	p.assess = a
	return p
}

var _ Planner = (*DefaultPlanner)(nil)

// Plan builds a Plan for credential without executing anything: it
// assesses risk (internal/risk.Assess), asks the PolicyEngine whether
// remediation is allowed and how many approvals it needs, and returns
// a Plan already in StatusApprovalRequired or StatusApproved
// accordingly. A policy denial produces no Plan at all — planning a
// remediation nobody is allowed to run isn't meaningful — the caller
// gets a descriptive error instead.
//
// action names the provider-specific remediation action this Plan
// proposes (e.g. "disable_access_key") — callers pick it since only
// they know which action a given provider/credential kind supports;
// DefaultPlanner does not hardcode provider knowledge. environment
// (e.g. "production", "development") is what policyengine.RemediationRule
// matches on alongside provider — see PolicyInput.Environment.
func (p *DefaultPlanner) Plan(ctx context.Context, credential cerberus.Credential, exposures []cerberus.Exposure, action, environment string) (Plan, error) {
	assess := p.assess
	if assess == nil {
		assess = risk.Assess
	}
	assessment := assess(credential, exposures)

	decision, err := p.policy.Evaluate(ctx, policyengine.PolicyInput{
		Domain:      "remediation",
		Action:      fmt.Sprintf("remediation:%s:%s", credential.Provider, action),
		Environment: environment,
		Attributes: map[string]string{
			"provider": credential.Provider,
		},
	})
	if err != nil {
		return Plan{}, fmt.Errorf("remediation: evaluating policy: %w", err)
	}
	if !decision.Allow {
		return Plan{}, fmt.Errorf("remediation: policy denies remediation for credential %s: %s", credential.ID, decision.Reason)
	}

	now := time.Now().UTC()
	plan := Plan{
		ID:           newPlanID(),
		CredentialID: credential.ID,
		Provider:     credential.Provider,
		Action:       action,
		// KeyFingerprint comes straight from the deduplicated
		// Credential identity. AccountID has no source yet:
		// cerberus.Credential doesn't carry a provider account id today
		// (see pkg/cerberus/credential.go), so it's left empty here.
		// That's fail-closed, not silently wrong — aws.Executor's
		// authorizedAccountIDs allowlist rejects an empty AccountID
		// rather than defaulting to allow, so no plan can execute
		// against a real account until account resolution is modeled
		// and wired through.
		Target: Target{Provider: credential.Provider, KeyFingerprint: credential.Fingerprint},
		Risk:         assessment,

		ApprovalRequired:  decision.ApprovalsRequired > 0,
		ApprovalsRequired: decision.ApprovalsRequired,

		DryRun: true,

		CreatedAt: now,
		UpdatedAt: now,
	}

	if decision.ApprovalsRequired > 0 {
		plan.Status = StatusApprovalRequired
		plan.Reason = fmt.Sprintf("policy requires %d approval(s): %s", decision.ApprovalsRequired, decision.Reason)
	} else {
		plan.Status = StatusApproved
		plan.Reason = "policy allows automatic execution: " + decision.Reason
	}

	return plan, nil
}

// Approve records approvalsGranted against plan and promotes it to
// StatusApproved once ApprovalsRequired is met. It is the only
// sanctioned way to move a Plan out of StatusApprovalRequired —
// nothing in this package self-approves a Plan (see
// docs/adr/0003-remediation-separation.md).
func Approve(plan Plan, approvalsGranted int) (Plan, error) {
	if plan.Status != StatusApprovalRequired && plan.Status != StatusProposed {
		return plan, fmt.Errorf("remediation: cannot approve a plan in status %s", plan.Status)
	}
	plan.ApprovalsGranted = approvalsGranted
	plan.UpdatedAt = time.Now().UTC()

	if approvalsGranted < plan.ApprovalsRequired {
		if err := requireTransition(plan.Status, StatusApprovalRequired); err != nil && plan.Status != StatusApprovalRequired {
			return plan, err
		}
		plan.Status = StatusApprovalRequired
		plan.Reason = fmt.Sprintf("%d of %d required approval(s) granted", approvalsGranted, plan.ApprovalsRequired)
		return plan, nil
	}

	if err := requireTransition(plan.Status, StatusApproved); err != nil {
		return plan, err
	}
	plan.Status = StatusApproved
	plan.Reason = fmt.Sprintf("%d of %d required approval(s) granted", approvalsGranted, plan.ApprovalsRequired)
	return plan, nil
}

func newPlanID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return "plan_" + hex.EncodeToString(buf)
}
