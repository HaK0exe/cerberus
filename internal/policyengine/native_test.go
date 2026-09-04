package policyengine_test

import (
	"context"
	"os"
	"testing"

	"github.com/HaK0exe/cerberus/internal/policyengine"
)

func loadTestPolicy(t *testing.T) policyengine.Policy {
	t.Helper()
	f, err := os.Open("../../testdata/policy/example.yaml")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()

	p, err := policyengine.LoadYAML(f)
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	return p
}

func TestEvaluate_RemediationRequiresApprovalsInProduction(t *testing.T) {
	engine := policyengine.NewNativeEngine(loadTestPolicy(t))

	decision, err := engine.Evaluate(context.Background(), policyengine.PolicyInput{
		Domain:      "remediation",
		Action:      "remediation:disable_key",
		Environment: "production",
		Attributes:  map[string]string{"provider": "aws"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allow {
		t.Errorf("expected production/aws remediation to be policy-permitted (pending approvals), got Allow=false, reason=%q", decision.Reason)
	}
	if decision.ApprovalsRequired != 2 {
		t.Errorf("ApprovalsRequired = %d, want 2", decision.ApprovalsRequired)
	}
	if decision.Reason == "" {
		t.Error("Reason must not be empty")
	}
}

func TestEvaluate_RemediationAutomaticInDevelopment(t *testing.T) {
	engine := policyengine.NewNativeEngine(loadTestPolicy(t))

	decision, err := engine.Evaluate(context.Background(), policyengine.PolicyInput{
		Domain:      "remediation",
		Action:      "remediation:disable_key",
		Environment: "development",
		Attributes:  map[string]string{"provider": "aws"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allow {
		t.Errorf("expected development/aws remediation to be allowed, got Allow=false, reason=%q", decision.Reason)
	}
	if decision.ApprovalsRequired != 0 {
		t.Errorf("ApprovalsRequired = %d, want 0 for automatic remediation", decision.ApprovalsRequired)
	}
}

func TestEvaluate_RemediationNoMatchDefaultsDeny(t *testing.T) {
	engine := policyengine.NewNativeEngine(loadTestPolicy(t))

	decision, err := engine.Evaluate(context.Background(), policyengine.PolicyInput{
		Domain:      "remediation",
		Action:      "remediation:disable_key",
		Environment: "staging", // not configured in the fixture
		Attributes:  map[string]string{"provider": "aws"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allow {
		t.Error("expected default-deny for an unconfigured environment")
	}
	if decision.Reason == "" {
		t.Error("Reason must not be empty for a default-deny decision")
	}
}

func TestEvaluate_MCPScopeInAllowlist(t *testing.T) {
	engine := policyengine.NewNativeEngine(loadTestPolicy(t))

	decision, err := engine.Evaluate(context.Background(), policyengine.PolicyInput{
		Domain:     "mcp",
		Action:     "mcp:tool",
		Attributes: map[string]string{"scope": "findings:read"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allow {
		t.Errorf("expected findings:read to be allowed, reason=%q", decision.Reason)
	}
}

func TestEvaluate_MCPScopeNotInAllowlist(t *testing.T) {
	engine := policyengine.NewNativeEngine(loadTestPolicy(t))

	decision, err := engine.Evaluate(context.Background(), policyengine.PolicyInput{
		Domain:     "mcp",
		Action:     "mcp:tool",
		Attributes: map[string]string{"scope": "remediation:execute"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allow {
		t.Error("expected remediation:execute to be denied — not in the fixture's allowlist")
	}
	if decision.Reason == "" {
		t.Error("Reason must not be empty for a denial")
	}
}

func TestEvaluate_ScanObeyRobotsTxtRoundTrips(t *testing.T) {
	engine := policyengine.NewNativeEngine(loadTestPolicy(t))

	decision, err := engine.Evaluate(context.Background(), policyengine.PolicyInput{
		Domain: "scan",
		Action: "obey_robots_txt",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allow {
		t.Error("fixture sets scan.obey_robots_txt: true, expected Allow=true")
	}
}

func TestEvaluate_UnknownDomainDefaultsDeny(t *testing.T) {
	engine := policyengine.NewNativeEngine(loadTestPolicy(t))

	decision, err := engine.Evaluate(context.Background(), policyengine.PolicyInput{
		Domain: "retention",
		Action: "purge",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allow {
		t.Error("expected default-deny for a domain with no policy support yet")
	}
	if decision.Reason == "" {
		t.Error("Reason must not be empty")
	}
}

// TestEvaluate_ReasonIsAlwaysNonEmpty is the explainability invariant:
// every PolicyDecision, allow or deny, must say why.
func TestEvaluate_ReasonIsAlwaysNonEmpty(t *testing.T) {
	engine := policyengine.NewNativeEngine(loadTestPolicy(t))
	ctx := context.Background()

	inputs := []policyengine.PolicyInput{
		{Domain: "remediation", Environment: "production", Attributes: map[string]string{"provider": "aws"}},
		{Domain: "remediation", Environment: "development", Attributes: map[string]string{"provider": "aws"}},
		{Domain: "remediation", Environment: "unknown", Attributes: map[string]string{"provider": "gcp"}},
		{Domain: "mcp", Attributes: map[string]string{"scope": "findings:read"}},
		{Domain: "mcp", Attributes: map[string]string{"scope": "nope"}},
		{Domain: "scan", Action: "obey_robots_txt"},
		{Domain: "scan", Action: "unsupported"},
		{Domain: "unknown-domain"},
	}

	for _, in := range inputs {
		decision, err := engine.Evaluate(ctx, in)
		if err != nil {
			t.Fatalf("Evaluate(%+v): %v", in, err)
		}
		if decision.Reason == "" {
			t.Errorf("Evaluate(%+v) returned an empty Reason", in)
		}
	}
}

func TestNewNativeEngine_ZeroValuePolicyDeniesEverything(t *testing.T) {
	engine := policyengine.NewNativeEngine(policyengine.Policy{})

	decision, err := engine.Evaluate(context.Background(), policyengine.PolicyInput{
		Domain:      "remediation",
		Environment: "production",
		Attributes:  map[string]string{"provider": "aws"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allow {
		t.Error("an empty/missing policy document must default-deny, not silently allow")
	}
}
