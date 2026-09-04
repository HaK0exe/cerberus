package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/HaK0exe/cerberus/internal/remediation"
)

// fakeIAM is an in-memory AWS IAM stand-in. No test in this file ever
// touches a real AWS account, SDK, or network call — this is the only
// implementation of IAMClient's function fields used anywhere here.
type fakeIAM struct {
	status map[string]KeyStatus // keyed by accessKeyID

	updateCalls int
	verifyCalls int

	failUpdateNTimes int // simulate N transient UpdateAccessKey failures before succeeding
	updateAttempts   int

	verifyMismatchOnce bool // report Active once even after a successful update, then Inactive
	verifyErrOnce      bool
}

func newFakeIAM(initial KeyStatus) *fakeIAM {
	return &fakeIAM{status: map[string]KeyStatus{"AKIATESTKEY": initial}}
}

func (f *fakeIAM) client() IAMClient {
	return IAMClient{
		UpdateAccessKey: func(_ context.Context, _, accessKeyID string, status KeyStatus) error {
			f.updateCalls++
			f.updateAttempts++
			if f.updateAttempts <= f.failUpdateNTimes {
				return errors.New("simulated transient AWS error")
			}
			f.status[accessKeyID] = status
			return nil
		},
		GetAccessKeyStatus: func(_ context.Context, _, accessKeyID string) (KeyStatus, error) {
			f.verifyCalls++
			if f.verifyErrOnce {
				f.verifyErrOnce = false
				return "", errors.New("simulated transient read error")
			}
			if f.verifyMismatchOnce {
				f.verifyMismatchOnce = false
				return KeyStatusActive, nil
			}
			return f.status[accessKeyID], nil
		},
	}
}

func approvedPlan(accountID string) remediation.Plan {
	return remediation.Plan{
		ID:     "plan_test",
		Status: remediation.StatusApproved,
		Target: remediation.Target{
			Provider:       "aws",
			AccountID:      accountID,
			KeyFingerprint: "AKIATESTKEY",
		},
	}
}

func TestExecute_OutOfScopeAccount_RejectedBeforeAnyClientCall(t *testing.T) {
	fake := newFakeIAM(KeyStatusActive)
	exec := NewExecutor(fake.client(), []string{"111111111111"})

	plan, err := exec.Execute(context.Background(), approvedPlan("222222222222"))
	if err == nil {
		t.Fatal("expected an error for an out-of-scope account")
	}
	if plan.Reason == "" {
		t.Error("Reason must not be empty")
	}
	if fake.updateCalls != 0 || fake.verifyCalls != 0 {
		t.Errorf("expected zero IAMClient calls, got update=%d verify=%d", fake.updateCalls, fake.verifyCalls)
	}
}

func TestExecute_InScopeApproved_DisablesAndVerifies(t *testing.T) {
	fake := newFakeIAM(KeyStatusActive)
	exec := NewExecutor(fake.client(), []string{"111111111111"})

	plan, err := exec.Execute(context.Background(), approvedPlan("111111111111"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if plan.Status != remediation.StatusVerified {
		t.Errorf("Status = %s, want %s", plan.Status, remediation.StatusVerified)
	}
	if fake.updateCalls != 1 {
		t.Errorf("UpdateAccessKey calls = %d, want 1", fake.updateCalls)
	}
	if fake.verifyCalls != 1 {
		t.Errorf("GetAccessKeyStatus calls = %d, want 1", fake.verifyCalls)
	}
	if plan.Reason == "" {
		t.Error("Reason must not be empty")
	}
}

func TestExecute_Idempotent_AlreadyVerifiedMakesNoClientCalls(t *testing.T) {
	fake := newFakeIAM(KeyStatusInactive)
	exec := NewExecutor(fake.client(), []string{"111111111111"})

	plan := approvedPlan("111111111111")
	plan.Status = remediation.StatusVerified

	got, err := exec.Execute(context.Background(), plan)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.Status != remediation.StatusVerified {
		t.Errorf("Status = %s, want %s", got.Status, remediation.StatusVerified)
	}
	if fake.updateCalls != 0 || fake.verifyCalls != 0 {
		t.Errorf("expected zero IAMClient calls on an already-Verified plan, got update=%d verify=%d", fake.updateCalls, fake.verifyCalls)
	}
}

func TestExecute_Idempotent_AlreadyDisabledDoesNotReDisable(t *testing.T) {
	fake := newFakeIAM(KeyStatusInactive)
	exec := NewExecutor(fake.client(), []string{"111111111111"})

	plan := approvedPlan("111111111111")
	plan.Status = remediation.StatusKeyDisabled

	got, err := exec.Execute(context.Background(), plan)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.Status != remediation.StatusVerified {
		t.Errorf("Status = %s, want %s", got.Status, remediation.StatusVerified)
	}
	if fake.updateCalls != 0 {
		t.Errorf("UpdateAccessKey should not be called again on a KeyDisabled plan, got %d calls", fake.updateCalls)
	}
	if fake.verifyCalls != 1 {
		t.Errorf("GetAccessKeyStatus calls = %d, want 1", fake.verifyCalls)
	}
}

func TestExecute_TransientUpdateFailure_LandsFailedThenRetrySucceeds(t *testing.T) {
	fake := newFakeIAM(KeyStatusActive)
	fake.failUpdateNTimes = 1
	exec := NewExecutor(fake.client(), []string{"111111111111"})

	plan, err := exec.Execute(context.Background(), approvedPlan("111111111111"))
	if err == nil {
		t.Fatal("expected the first Execute to fail (simulated transient error)")
	}
	if plan.Status != remediation.StatusFailed {
		t.Fatalf("Status = %s, want %s", plan.Status, remediation.StatusFailed)
	}
	if plan.Reason == "" {
		t.Error("Reason must not be empty")
	}

	// Retry: the fake now succeeds.
	plan, err = exec.Execute(context.Background(), plan)
	if err != nil {
		t.Fatalf("retry Execute: %v", err)
	}
	if plan.Status != remediation.StatusVerified {
		t.Errorf("after retry, Status = %s, want %s", plan.Status, remediation.StatusVerified)
	}
	if fake.updateCalls != 2 {
		t.Errorf("expected exactly 2 UpdateAccessKey attempts (1 failed + 1 retry), got %d", fake.updateCalls)
	}
}

func TestExecute_VerificationMismatch_StaysDisabledNotVerified(t *testing.T) {
	fake := newFakeIAM(KeyStatusActive)
	fake.verifyMismatchOnce = true
	exec := NewExecutor(fake.client(), []string{"111111111111"})

	plan, err := exec.Execute(context.Background(), approvedPlan("111111111111"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if plan.Status != remediation.StatusKeyDisabled {
		t.Errorf("Status = %s, want %s (verification mismatch must not auto-promote)", plan.Status, remediation.StatusKeyDisabled)
	}
	if plan.Reason == "" {
		t.Error("Reason must not be empty")
	}
	if fake.updateCalls != 1 {
		t.Errorf("UpdateAccessKey should have been called exactly once, got %d", fake.updateCalls)
	}

	// Retry verification only: no second UpdateAccessKey call.
	plan, err = exec.Execute(context.Background(), plan)
	if err != nil {
		t.Fatalf("retry Execute: %v", err)
	}
	if plan.Status != remediation.StatusVerified {
		t.Errorf("after retry, Status = %s, want %s", plan.Status, remediation.StatusVerified)
	}
	if fake.updateCalls != 1 {
		t.Errorf("UpdateAccessKey must not be called again on verification retry, got %d calls total", fake.updateCalls)
	}
}

func TestExecute_RejectsNonApprovedStatus(t *testing.T) {
	fake := newFakeIAM(KeyStatusActive)
	exec := NewExecutor(fake.client(), []string{"111111111111"})

	plan := approvedPlan("111111111111")
	plan.Status = remediation.StatusProposed

	_, err := exec.Execute(context.Background(), plan)
	if err == nil {
		t.Fatal("expected Execute to reject a Proposed (not Approved) plan")
	}
	if fake.updateCalls != 0 {
		t.Errorf("expected zero IAMClient calls, got %d", fake.updateCalls)
	}
}

func TestNewExecutor_EmptyAllowlistAuthorizesNothing(t *testing.T) {
	fake := newFakeIAM(KeyStatusActive)
	exec := NewExecutor(fake.client(), nil)

	_, err := exec.Execute(context.Background(), approvedPlan("111111111111"))
	if err == nil {
		t.Fatal("an Executor with no configured scope must refuse everything")
	}
	if fake.updateCalls != 0 {
		t.Errorf("expected zero IAMClient calls, got %d", fake.updateCalls)
	}
}
