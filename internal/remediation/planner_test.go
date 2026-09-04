package remediation

import (
	"context"
	"testing"
	"time"

	"github.com/HaK0exe/cerberus/internal/policyengine"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

type fakePolicyEngine struct {
	decision policyengine.PolicyDecision
	err      error
}

func (f fakePolicyEngine) Evaluate(context.Context, policyengine.PolicyInput) (policyengine.PolicyDecision, error) {
	return f.decision, f.err
}

func testCredential() cerberus.Credential {
	return cerberus.Credential{
		ID:          "cred_test",
		Provider:    "aws",
		Kind:        "aws-access-key-id",
		Fingerprint: "AKIATESTKEY",
		FirstSeen:   time.Now().Add(-24 * time.Hour),
		LastSeen:    time.Now(),
	}
}

func fixedAssessor(a cerberus.RiskAssessment) RiskAssessor {
	return func(cerberus.Credential, []cerberus.Exposure) cerberus.RiskAssessment { return a }
}

func TestPlanner_PolicyRequiresApprovals_PlanIsApprovalRequired(t *testing.T) {
	engine := fakePolicyEngine{decision: policyengine.PolicyDecision{
		Allow: true, Reason: "production requires review", ApprovalsRequired: 2,
	}}
	p := NewPlanner(engine).WithRiskAssessor(fixedAssessor(cerberus.RiskAssessment{Level: cerberus.RiskHigh}))

	plan, err := p.Plan(context.Background(), testCredential(), nil, "disable_access_key", "production")
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Status != StatusApprovalRequired {
		t.Errorf("Status = %s, want %s", plan.Status, StatusApprovalRequired)
	}
	if !plan.ApprovalRequired || plan.ApprovalsRequired != 2 {
		t.Errorf("ApprovalRequired/ApprovalsRequired = %v/%d, want true/2", plan.ApprovalRequired, plan.ApprovalsRequired)
	}
	if plan.Reason == "" {
		t.Error("Reason must not be empty")
	}
	if plan.Risk.Level != cerberus.RiskHigh {
		t.Errorf("Risk not propagated onto Plan: got %v", plan.Risk)
	}
}

func TestPlanner_TargetCarriesCredentialFingerprint(t *testing.T) {
	engine := fakePolicyEngine{decision: policyengine.PolicyDecision{Allow: true}}
	p := NewPlanner(engine)

	plan, err := p.Plan(context.Background(), testCredential(), nil, "disable_access_key", "production")
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Target.KeyFingerprint != "AKIATESTKEY" {
		t.Errorf("Target.KeyFingerprint = %q, want %q (credential.Fingerprint)", plan.Target.KeyFingerprint, "AKIATESTKEY")
	}
	if plan.Target.Provider != "aws" {
		t.Errorf("Target.Provider = %q, want %q", plan.Target.Provider, "aws")
	}
}

func TestPlanner_PolicyAllowsAutomatic_PlanIsApproved(t *testing.T) {
	engine := fakePolicyEngine{decision: policyengine.PolicyDecision{
		Allow: true, Reason: "development auto-disable", ApprovalsRequired: 0,
	}}
	p := NewPlanner(engine)

	plan, err := p.Plan(context.Background(), testCredential(), nil, "disable_access_key", "production")
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Status != StatusApproved {
		t.Errorf("Status = %s, want %s", plan.Status, StatusApproved)
	}
	if plan.ApprovalRequired {
		t.Error("ApprovalRequired should be false when policy requires 0 approvals")
	}
}

func TestPlanner_PolicyDenies_NoPlanProduced(t *testing.T) {
	engine := fakePolicyEngine{decision: policyengine.PolicyDecision{
		Allow: false, Reason: "remediation disabled for this provider",
	}}
	p := NewPlanner(engine)

	_, err := p.Plan(context.Background(), testCredential(), nil, "disable_access_key", "production")
	if err == nil {
		t.Fatal("expected an error when policy denies remediation")
	}
}

func TestPlanner_NeverCallsExecutor(t *testing.T) {
	// Structural: DefaultPlanner has no reference to any Executor/IAMClient
	// type at all — Plan cannot perform I/O it wasn't given. This test
	// exists to document the invariant; the compiler already enforces
	// it (DefaultPlanner's fields are policy+assess only).
	engine := fakePolicyEngine{decision: policyengine.PolicyDecision{Allow: true}}
	p := NewPlanner(engine)
	if _, err := p.Plan(context.Background(), testCredential(), nil, "disable_access_key", "production"); err != nil {
		t.Fatalf("Plan: %v", err)
	}
}

func TestApprove_PromotesOnceThresholdMet(t *testing.T) {
	plan := Plan{Status: StatusApprovalRequired, ApprovalsRequired: 2}

	plan, err := Approve(plan, 1)
	if err != nil {
		t.Fatalf("Approve(1): %v", err)
	}
	if plan.Status != StatusApprovalRequired {
		t.Errorf("with 1/2 approvals, Status = %s, want still %s", plan.Status, StatusApprovalRequired)
	}

	plan, err = Approve(plan, 2)
	if err != nil {
		t.Fatalf("Approve(2): %v", err)
	}
	if plan.Status != StatusApproved {
		t.Errorf("with 2/2 approvals, Status = %s, want %s", plan.Status, StatusApproved)
	}
}

func TestApprove_RejectsWrongStartingStatus(t *testing.T) {
	plan := Plan{Status: StatusExecuting}
	if _, err := Approve(plan, 5); err == nil {
		t.Error("expected Approve to reject a plan already Executing")
	}
}
