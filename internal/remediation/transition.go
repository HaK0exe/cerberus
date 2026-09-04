package remediation

import "fmt"

// transitions is the complete legal Status state machine. Any move not
// listed here is rejected by CanTransition — see remediation.go's
// Status constants for what each state means.
var transitions = map[Status][]Status{
	StatusProposed:         {StatusApprovalRequired, StatusApproved, StatusCancelled},
	StatusApprovalRequired: {StatusApproved, StatusCancelled},
	StatusApproved:         {StatusExecuting, StatusCancelled},
	StatusExecuting:        {StatusKeyDisabled, StatusFailed},
	// A Failed execution is retryable: Executing is the only way back
	// in, never a silent auto-recovery.
	StatusFailed: {StatusExecuting},
	// KeyDisabled is re-verifiable without repeating the disable call
	// (idempotent retry): it can re-attempt verification (staying
	// KeyDisabled on a mismatch/error) or be promoted to Verified.
	StatusKeyDisabled: {StatusKeyDisabled, StatusVerified, StatusKeyDeleted},
	StatusVerified:    {StatusKeyDeleted},
	// Terminal states: no outbound transitions.
	StatusKeyDeleted: {},
	StatusCancelled:  {},
	StatusMonitoring: {StatusKeyDisabled, StatusVerified},
}

// CanTransition reports whether moving a Plan from `from` to `to` is a
// legal step in the remediation lifecycle. Every Status mutation in
// this package (and any provider implementation) must be gated by this
// function — see docs/adr/0010-remediation-v2.md.
func CanTransition(from, to Status) bool {
	for _, allowed := range transitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

// requireTransition returns a descriptive error if from->to is not a
// legal transition, otherwise nil.
func requireTransition(from, to Status) error {
	if from == to {
		return nil // idempotent no-op transitions are handled by callers, not rejected here
	}
	if !CanTransition(from, to) {
		return fmt.Errorf("remediation: illegal status transition %s -> %s", from, to)
	}
	return nil
}
