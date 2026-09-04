package policyengine

import (
	"context"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Policy is the native YAML policy document. It is deliberately small:
// three domains, each with just enough shape to answer the questions
// Cerberus needs today (remediation approval counts, MCP tool scopes,
// scan behavior flags) rather than a general-purpose rule DSL. Add a
// field here — not a new mini-language — when a new domain needs one.
type Policy struct {
	Remediation []RemediationRule `yaml:"remediation"`
	MCP         MCPPolicy         `yaml:"mcp"`
	Scan        ScanPolicy        `yaml:"scan"`
}

// RemediationRule scopes an approval requirement to a provider and
// environment. The first rule matching PolicyInput.Attributes["provider"]
// and PolicyInput.Environment wins; rules are evaluated in document
// order so a more specific rule should be listed before a broader one.
type RemediationRule struct {
	Provider    string `yaml:"provider"`
	Environment string `yaml:"environment"`

	// Automatic, when true, allows the action with zero approvals
	// (e.g. "development" disabling a key on detection). When false,
	// the action is still policy-permitted but gated on collecting
	// ApprovalsRequired approvals through the remediation approval
	// workflow — PolicyEngine only decides the count, it never itself
	// grants or checks approvals.
	Automatic         bool `yaml:"automatic"`
	ApprovalsRequired int  `yaml:"approvals_required"`
}

// MCPPolicy is a scope allowlist. A caller's PolicyInput.Attributes["scope"]
// must appear in Allow for the call to be permitted.
type MCPPolicy struct {
	Allow []string `yaml:"allow"`
}

// ScanPolicy holds simple boolean scan-behavior flags.
type ScanPolicy struct {
	ObeyRobotsTxt bool `yaml:"obey_robots_txt"`
}

// LoadYAML parses a Policy document. An empty or missing document is
// valid YAML (zero-value Policy) — NativeEngine's default-deny
// behavior then applies to everything, which is the safe failure mode
// for a missing/misconfigured policy file.
func LoadYAML(r io.Reader) (Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(r)
	if err := dec.Decode(&p); err != nil && err != io.EOF {
		return Policy{}, fmt.Errorf("policyengine: parsing policy YAML: %w", err)
	}
	return p, nil
}

// NativeEngine is a native, in-process PolicyEngine backed by a Policy
// document. It default-denies: any domain, action, or attribute
// combination with no matching rule is denied with an explanatory
// Reason, rather than silently allowed. This mirrors ADR-0001/0003's
// posture — an un-configured control-plane decision must fail closed,
// since Cerberus's failure mode of "policy didn't say no" must never
// be read as "yes".
//
// NativeEngine only decides; see the package doc comment for the
// definition/evaluation/enforcement split.
type NativeEngine struct {
	policy Policy
}

var _ PolicyEngine = (*NativeEngine)(nil)

// NewNativeEngine constructs a NativeEngine from an already-loaded
// Policy (see LoadYAML).
func NewNativeEngine(policy Policy) *NativeEngine {
	return &NativeEngine{policy: policy}
}

func (e *NativeEngine) Evaluate(_ context.Context, input PolicyInput) (PolicyDecision, error) {
	switch input.Domain {
	case "remediation":
		return e.evaluateRemediation(input), nil
	case "mcp":
		return e.evaluateMCP(input), nil
	case "scan":
		return e.evaluateScan(input), nil
	default:
		return PolicyDecision{
			Allow:  false,
			Reason: fmt.Sprintf("unknown policy domain %q: default-deny applies", input.Domain),
		}, nil
	}
}

func (e *NativeEngine) evaluateRemediation(input PolicyInput) PolicyDecision {
	provider := input.Attributes["provider"]

	for _, rule := range e.policy.Remediation {
		if rule.Provider != provider || rule.Environment != input.Environment {
			continue
		}

		if rule.Automatic {
			return PolicyDecision{
				Allow:  true,
				Reason: fmt.Sprintf("environment %q is configured for automatic remediation of provider %q (no approval required)", input.Environment, provider),
				Attributes: map[string]string{
					"provider":    provider,
					"environment": input.Environment,
				},
			}
		}

		// A non-automatic rule must gate on at least one approval. A
		// rule that sets automatic: false but leaves approvals_required
		// unset (Go zero value 0) is a misconfiguration, not a request
		// for automatic execution — treat it as requiring one approval
		// rather than silently falling through to the same
		// ApprovalsRequired == 0 result Plan() reads as "auto-approve".
		approvalsRequired := rule.ApprovalsRequired
		if approvalsRequired <= 0 {
			approvalsRequired = 1
		}

		return PolicyDecision{
			Allow:             true,
			Reason:            fmt.Sprintf("policy requires %d approval(s) for provider %q in environment %q before remediation can execute", approvalsRequired, provider, input.Environment),
			ApprovalsRequired: approvalsRequired,
			Attributes: map[string]string{
				"provider":    provider,
				"environment": input.Environment,
			},
		}
	}

	return PolicyDecision{
		Allow:  false,
		Reason: fmt.Sprintf("no remediation policy configured for provider %q in environment %q: default-deny applies", provider, input.Environment),
	}
}

func (e *NativeEngine) evaluateMCP(input PolicyInput) PolicyDecision {
	scope := input.Attributes["scope"]

	for _, allowed := range e.policy.MCP.Allow {
		if allowed == scope {
			return PolicyDecision{
				Allow:  true,
				Reason: fmt.Sprintf("scope %q is present in the mcp allowlist", scope),
			}
		}
	}

	return PolicyDecision{
		Allow:  false,
		Reason: fmt.Sprintf("scope %q is not present in the mcp allowlist: default-deny applies", scope),
	}
}

func (e *NativeEngine) evaluateScan(input PolicyInput) PolicyDecision {
	switch input.Action {
	case "obey_robots_txt":
		return PolicyDecision{
			Allow:  e.policy.Scan.ObeyRobotsTxt,
			Reason: fmt.Sprintf("scan.obey_robots_txt is configured as %v", e.policy.Scan.ObeyRobotsTxt),
		}
	default:
		return PolicyDecision{
			Allow:  false,
			Reason: fmt.Sprintf("no scan policy configured for action %q: default-deny applies", input.Action),
		}
	}
}
