package remediation

import "testing"

func TestCanTransition_LegalPaths(t *testing.T) {
	cases := []struct{ from, to Status }{
		{StatusProposed, StatusApprovalRequired},
		{StatusProposed, StatusApproved},
		{StatusApprovalRequired, StatusApproved},
		{StatusApproved, StatusExecuting},
		{StatusExecuting, StatusKeyDisabled},
		{StatusExecuting, StatusFailed},
		{StatusFailed, StatusExecuting},
		{StatusKeyDisabled, StatusVerified},
	}
	for _, c := range cases {
		if !CanTransition(c.from, c.to) {
			t.Errorf("expected %s -> %s to be legal", c.from, c.to)
		}
	}
}

func TestCanTransition_IllegalPaths(t *testing.T) {
	cases := []struct{ from, to Status }{
		{StatusProposed, StatusExecuting}, // skips approval
		{StatusProposed, StatusVerified},  // skips everything
		{StatusApprovalRequired, StatusExecuting},
		{StatusVerified, StatusExecuting},  // terminal-ish, only ->KeyDeleted
		{StatusCancelled, StatusApproved},  // terminal
		{StatusKeyDeleted, StatusApproved}, // terminal
	}
	for _, c := range cases {
		if CanTransition(c.from, c.to) {
			t.Errorf("expected %s -> %s to be illegal", c.from, c.to)
		}
	}
}

func TestRequireTransition_SameStateIsNoop(t *testing.T) {
	if err := requireTransition(StatusKeyDisabled, StatusKeyDisabled); err != nil {
		t.Errorf("same-state transition should be a no-op, got error: %v", err)
	}
}

func TestRequireTransition_IllegalReturnsDescriptiveError(t *testing.T) {
	err := requireTransition(StatusProposed, StatusExecuting)
	if err == nil {
		t.Fatal("expected an error for an illegal transition")
	}
	if err.Error() == "" {
		t.Error("transition error must be descriptive, not empty")
	}
}
