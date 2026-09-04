package mcp

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/HaK0exe/cerberus/internal/audit"
	"github.com/HaK0exe/cerberus/internal/credentials"
	"github.com/HaK0exe/cerberus/internal/findings"
	"github.com/HaK0exe/cerberus/internal/policyengine"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// fakeAuditSink records every event so tests can assert a denial still
// produced an audit entry.
type fakeAuditSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (f *fakeAuditSink) Record(_ context.Context, e audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return nil
}

func (f *fakeAuditSink) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

// allowAllPolicy is a PolicyEngine that always allows with zero
// approvals — used where the test isn't exercising the policy stage.
type allowAllPolicy struct{}

func (allowAllPolicy) Evaluate(context.Context, policyengine.PolicyInput) (policyengine.PolicyDecision, error) {
	return policyengine.PolicyDecision{Allow: true, Reason: "test: allow all"}, nil
}

// denyAllPolicy is a PolicyEngine that always denies.
type denyAllPolicy struct{}

func (denyAllPolicy) Evaluate(context.Context, policyengine.PolicyInput) (policyengine.PolicyDecision, error) {
	return policyengine.PolicyDecision{Allow: false, Reason: "test: deny all"}, nil
}

func seededFindingsStore(t *testing.T) (*findings.MemStore, cerberus.Finding) {
	t.Helper()
	store := findings.NewMemStore()
	f := cerberus.Finding{
		ID:           "fnd_test1",
		RuleID:       "aws-access-key-id",
		Type:         "aws-access-key-id",
		Severity:     cerberus.SeverityHigh,
		Confidence:   0.97,
		Fingerprint:  "cerberus:hmac-sha256:deadbeef",
		MaskedPrefix: "AKIA****************",
		Path:         "a.env",
		State:        cerberus.StateOpen,
		CreatedAt:    time.Now().UTC(),
		Provenance: cerberus.DetectionProvenance{
			RuleID: "aws-access-key-id",
			Signals: []cerberus.Signal{
				{Name: "rule_base_confidence", Score: 0.9, Reason: "declared base confidence"},
			},
		},
	}
	if err := store.Put(context.Background(), f); err != nil {
		t.Fatalf("seed Put: %v", err)
	}
	return store, f
}

func TestDispatch_DeniesWithoutRequiredScope_AndAudits(t *testing.T) {
	store, _ := seededFindingsStore(t)
	sink := &fakeAuditSink{}
	srv := NewServer(allowAllPolicy{}, NewRateLimiter(100, 100), sink, &ListFindingsTool{Store: store})

	principal := Principal{ID: "agent-1"} // no scopes granted
	result := srv.Dispatch(context.Background(), principal, ToolCall{Name: "cerberus_list_findings"})

	if !result.IsError {
		t.Fatal("expected denial, got success")
	}
	if result.ErrorMessage == "" {
		t.Error("denial must carry a non-empty reason")
	}
	if sink.count() != 1 {
		t.Fatalf("expected 1 audit event for the denied call, got %d", sink.count())
	}
}

func TestDispatch_DeniesOnPolicyReject(t *testing.T) {
	store, _ := seededFindingsStore(t)
	sink := &fakeAuditSink{}
	srv := NewServer(denyAllPolicy{}, NewRateLimiter(100, 100), sink, &ListFindingsTool{Store: store})

	principal := Principal{ID: "agent-1", GrantedScopes: []Scope{ScopeFindingsRead}}
	result := srv.Dispatch(context.Background(), principal, ToolCall{Name: "cerberus_list_findings"})

	if !result.IsError {
		t.Fatal("expected policy denial, got success")
	}
	if result.ErrorMessage == "" {
		t.Error("policy denial must carry a non-empty reason")
	}
}

func TestDispatch_DeniesOnRateLimitExhaustion(t *testing.T) {
	store, _ := seededFindingsStore(t)
	sink := &fakeAuditSink{}
	limiter := NewRateLimiter(0, 1) // burst of exactly 1, no refill
	srv := NewServer(allowAllPolicy{}, limiter, sink, &ListFindingsTool{Store: store})

	principal := Principal{ID: "agent-1", GrantedScopes: []Scope{ScopeFindingsRead}}
	call := ToolCall{Name: "cerberus_list_findings"}

	first := srv.Dispatch(context.Background(), principal, call)
	if first.IsError {
		t.Fatalf("first call should succeed within burst, got error: %s", first.ErrorMessage)
	}

	second := srv.Dispatch(context.Background(), principal, call)
	if !second.IsError {
		t.Fatal("second call should be rate-limited")
	}
	if second.ErrorMessage == "" {
		t.Error("rate-limit denial must carry a non-empty reason")
	}
}

func TestDispatch_AuthorizedGetFinding_ReturnsSafeContentOnly(t *testing.T) {
	store, seeded := seededFindingsStore(t)
	sink := &fakeAuditSink{}
	srv := NewServer(allowAllPolicy{}, NewRateLimiter(100, 100), sink, &GetFindingTool{Store: store})

	principal := Principal{ID: "agent-1", GrantedScopes: []Scope{ScopeFindingsRead}}
	result := srv.Dispatch(context.Background(), principal, ToolCall{
		Name:      "cerberus_get_finding",
		Arguments: map[string]any{"finding_id": seeded.ID},
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %s", result.ErrorMessage)
	}
	f, ok := result.Content.(cerberus.Finding)
	if !ok {
		t.Fatalf("expected cerberus.Finding content, got %T", result.Content)
	}
	if f.ID != seeded.ID {
		t.Errorf("returned finding ID = %q, want %q", f.ID, seeded.ID)
	}
	if f.MaskedPrefix != "AKIA****************" {
		t.Errorf("unexpected masked prefix leaked through: %q", f.MaskedPrefix)
	}
	// The Finding type structurally has no raw-secret field (see
	// pkg/cerberus/finding.go / ADR-0001) — asserting the concrete type
	// round-tripped unchanged is the strongest check available here
	// without duplicating that struct's field list.
}

func TestDispatch_ExplainFinding_ReturnsSameSignalsAsProvenance(t *testing.T) {
	store, seeded := seededFindingsStore(t)
	sink := &fakeAuditSink{}
	srv := NewServer(allowAllPolicy{}, NewRateLimiter(100, 100), sink, &ExplainFindingTool{Store: store})

	principal := Principal{ID: "agent-1", GrantedScopes: []Scope{ScopeFindingsRead}}
	result := srv.Dispatch(context.Background(), principal, ToolCall{
		Name:      "cerberus_explain_finding",
		Arguments: map[string]any{"finding_id": seeded.ID},
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %s", result.ErrorMessage)
	}
	prov, ok := result.Content.(cerberus.DetectionProvenance)
	if !ok {
		t.Fatalf("expected cerberus.DetectionProvenance content, got %T", result.Content)
	}
	if len(prov.Signals) != len(seeded.Provenance.Signals) {
		t.Fatalf("signal count mismatch: got %d, want %d", len(prov.Signals), len(seeded.Provenance.Signals))
	}
	if prov.Signals[0].Name != seeded.Provenance.Signals[0].Name {
		t.Errorf("signal mismatch: got %+v, want %+v", prov.Signals[0], seeded.Provenance.Signals[0])
	}
}

func TestDispatch_UnknownTool_Denied(t *testing.T) {
	sink := &fakeAuditSink{}
	srv := NewServer(allowAllPolicy{}, NewRateLimiter(100, 100), sink)

	result := srv.Dispatch(context.Background(), Principal{ID: "agent-1"}, ToolCall{Name: "cerberus_does_not_exist"})
	if !result.IsError || result.ErrorMessage == "" {
		t.Fatal("unknown tool must be denied with a non-empty reason")
	}
}

func TestDispatch_RejectsUnexpectedArgument(t *testing.T) {
	store, seeded := seededFindingsStore(t)
	sink := &fakeAuditSink{}
	srv := NewServer(allowAllPolicy{}, NewRateLimiter(100, 100), sink, &GetFindingTool{Store: store})

	principal := Principal{ID: "agent-1", GrantedScopes: []Scope{ScopeFindingsRead}}
	result := srv.Dispatch(context.Background(), principal, ToolCall{
		Name: "cerberus_get_finding",
		Arguments: map[string]any{
			"finding_id":  seeded.ID,
			"secret_hint": "AKIAABCDEFGHIJKLMNOP", // not a declared argument
		},
	})

	if !result.IsError {
		t.Fatal("expected denial for an undeclared argument key")
	}
	if result.ErrorMessage == "" {
		t.Error("argument-rejection denial must carry a non-empty reason")
	}
}

func TestDispatch_ExecuteRemediation_RequiresScope_AndNeverActsPrivileged(t *testing.T) {
	sink := &fakeAuditSink{}
	srv := NewServer(allowAllPolicy{}, NewRateLimiter(100, 100), sink, &ExecuteRemediationTool{})

	// Without the scope: denied before Handle ever runs.
	noScope := Principal{ID: "agent-1"}
	denied := srv.Dispatch(context.Background(), noScope, ToolCall{
		Name:      "cerberus_execute_remediation",
		Arguments: map[string]any{"remediation_id": "rem_1"},
	})
	if !denied.IsError {
		t.Fatal("cerberus_execute_remediation must be unreachable without remediation:execute scope")
	}

	// With the scope: Handle runs, but performs no privileged action —
	// it must report that execution is not wired, not simulate success.
	withScope := Principal{ID: "agent-2", GrantedScopes: []Scope{ScopeRemediationExecute}}
	result := srv.Dispatch(context.Background(), withScope, ToolCall{
		Name:      "cerberus_execute_remediation",
		Arguments: map[string]any{"remediation_id": "rem_1"},
	})
	if !result.IsError {
		t.Fatal("cerberus_execute_remediation must not report success: no Executor is wired yet")
	}
	if result.ErrorMessage == "" {
		t.Error("must explain why execution did not happen")
	}
}

func TestDispatch_RequestRemediation_NeverAcceptsRawSecretArgument(t *testing.T) {
	sink := &fakeAuditSink{}
	srv := NewServer(allowAllPolicy{}, NewRateLimiter(100, 100), sink, &RequestRemediationTool{})

	principal := Principal{ID: "agent-1", GrantedScopes: []Scope{ScopeRemediationRequest}}
	result := srv.Dispatch(context.Background(), principal, ToolCall{
		Name: "cerberus_request_remediation",
		Arguments: map[string]any{
			"secret_value": "AKIAABCDEFGHIJKLMNOP", // not a declared argument
		},
	})

	if !result.IsError {
		t.Fatal("a raw-secret-shaped argument key must be rejected")
	}
}

func TestAllDenials_HaveNonEmptyReason(t *testing.T) {
	store, _ := seededFindingsStore(t)
	credStore := credentials.NewMemStore()
	sink := &fakeAuditSink{}
	srv := NewServer(denyAllPolicy{}, NewRateLimiter(100, 100), sink,
		&ListFindingsTool{Store: store},
		&ListCredentialsTool{Store: credStore},
		&ListIncidentsTool{Store: credStore},
	)

	principal := Principal{ID: "agent-1", GrantedScopes: []Scope{
		ScopeFindingsRead, ScopeCredentialsRead, ScopeIncidentsRead,
	}}

	for _, tool := range []string{"cerberus_list_findings", "cerberus_list_credentials", "cerberus_list_incidents"} {
		result := srv.Dispatch(context.Background(), principal, ToolCall{Name: tool})
		if !result.IsError {
			t.Errorf("%s: expected policy denial", tool)
		}
		if result.ErrorMessage == "" {
			t.Errorf("%s: denial reason must not be empty", tool)
		}
	}
}
