// Package policyengine provides a single, explainable decision point
// for the control-plane policy questions Cerberus needs to answer —
// "is this remediation allowed, and how many approvals does it need?",
// "does this MCP caller's scope include this tool?", "should this
// scanner obey robots.txt?" — instead of scattering `if` statements
// across the remediation, MCP, and scanner packages.
//
// This package only decides. It never itself blocks an HTTP request,
// refuses a remediation call, or throttles a scan: callers in
// internal/mcp, internal/remediation, and internal/scanner are
// responsible for enforcing the PolicyDecision they get back. See
// docs/adr/0006-policy-engine.md for the definition/evaluation/
// enforcement split this is built around.
package policyengine

import "context"

// PolicyInput is what a caller asks the PolicyEngine to decide on.
//
// Domain names the policy area ("remediation", "mcp", "scan", ...).
// Action names the specific thing being evaluated within that domain
// (e.g. "remediation:disable_key", "mcp:tool", "scan:obey_robots_txt").
// Attributes carries whatever domain-specific context a rule might
// match against (e.g. "provider": "aws", "environment": "production",
// "scope": "findings:read") — deliberately a flat string map rather
// than per-domain structs, so PolicyEngine stays a single interface
// callers can share instead of one per domain.
type PolicyInput struct {
	Domain      string
	Action      string
	Environment string
	Attributes  map[string]string
}

// PolicyDecision is the PolicyEngine's answer. Reason is never empty —
// an allow, a deny, and an approval requirement must all be
// explainable, the same invariant cerberus.Signal enforces for
// detection scoring. ApprovalsRequired is meaningful only when Allow
// is true and the domain uses an approval workflow (e.g.
// remediation); it is 0 otherwise. Attributes echoes back any
// decision-relevant values a caller may want to log or display
// (e.g. which rule matched) without requiring a second lookup.
type PolicyDecision struct {
	Allow             bool
	Reason            string
	ApprovalsRequired int
	Attributes        map[string]string
}

// PolicyEngine evaluates a PolicyInput into a PolicyDecision. It has
// exactly one method so that additional domains (retention, severity,
// ...) never require a new interface — only new PolicyInput.Domain
// values and, for the native engine, new Policy schema fields.
type PolicyEngine interface {
	Evaluate(ctx context.Context, input PolicyInput) (PolicyDecision, error)
}
