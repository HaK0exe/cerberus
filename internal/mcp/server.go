package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/HaK0exe/cerberus/internal/audit"
	"github.com/HaK0exe/cerberus/internal/policyengine"
)

// Principal is the authenticated caller of a tool call. Authentication
// itself — verifying who this is — happens upstream of this package,
// in a future stdio/HTTP transport; Server only ever sees the result.
type Principal struct {
	ID            string
	GrantedScopes []Scope
}

func (p Principal) hasScope(s Scope) bool {
	for _, g := range p.GrantedScopes {
		if g == s {
			return true
		}
	}
	return false
}

// Server dispatches ToolCalls through the fixed pipeline. It never
// trusts a caller's own claims about its scopes — see Dispatch.
type Server struct {
	tools   map[string]Tool
	policy  policyengine.PolicyEngine
	limiter *RateLimiter
	audit   audit.Sink
}

// NewServer wires a Server. sink may be nil, in which case audit
// events are discarded (audit.NopSink) — never use that in production,
// only in tests or explicitly audit-disabled configurations, per
// internal/audit's own doc comment.
func NewServer(policy policyengine.PolicyEngine, limiter *RateLimiter, sink audit.Sink, tools ...Tool) *Server {
	reg := make(map[string]Tool, len(tools))
	for _, t := range tools {
		reg[t.Name()] = t
	}
	if sink == nil {
		sink = audit.NopSink{}
	}
	return &Server{tools: reg, policy: policy, limiter: limiter, audit: sink}
}

// Dispatch runs one ToolCall through Authorization → Policy → Scope
// validation → Rate limiting → Audit → Execution, in that order,
// denying at the first stage that fails.
//
// Denials are always a ToolResult with IsError=true and a non-empty
// ErrorMessage — never a raw Go error a transport might leak verbatim
// — and every call, allowed or denied, is audited before Execution
// runs, so a denied/failed attempt is never invisible to the audit
// trail.
func (s *Server) Dispatch(ctx context.Context, principal Principal, call ToolCall) ToolResult {
	tool, ok := s.tools[call.Name]
	if !ok {
		return s.deny(ctx, principal, call, "denied_unknown_tool", fmt.Sprintf("no such tool %q", call.Name))
	}

	// Authorization: scopes come ONLY from the authenticated Principal,
	// never from call.RequestedScopes — a caller cannot grant itself
	// access by simply asking for a scope in the request. This is the
	// "never trust an agent because it knows a tool name" boundary.
	for _, required := range tool.RequiredScopes() {
		if !principal.hasScope(required) {
			return s.deny(ctx, principal, call, "denied_authz",
				fmt.Sprintf("principal %q lacks required scope %q for tool %q", principal.ID, required, tool.Name()))
		}
	}

	decision, err := s.policy.Evaluate(ctx, policyInputFor(tool))
	if err != nil {
		return s.deny(ctx, principal, call, "denied_policy_error", fmt.Sprintf("policy evaluation failed: %v", err))
	}
	if !decision.Allow {
		return s.deny(ctx, principal, call, "denied_policy", decision.Reason)
	}
	if decision.ApprovalsRequired > 0 {
		// PolicyEngine only decides the approval count — it never
		// tracks or grants approvals itself (see docs/adr/0006). Until
		// a remediation approval workflow (Phase K) confirms those
		// approvals were collected, Dispatch must not execute.
		return s.deny(ctx, principal, call, "denied_approval_pending",
			fmt.Sprintf("requires %d approval(s) before execution: %s", decision.ApprovalsRequired, decision.Reason))
	}

	if reason := validateArguments(tool, call.Arguments); reason != "" {
		return s.deny(ctx, principal, call, "denied_arguments", reason)
	}

	if s.limiter != nil && !s.limiter.Allow(principal.ID) {
		return s.deny(ctx, principal, call, "denied_rate_limited", fmt.Sprintf("principal %q exceeded its call rate", principal.ID))
	}

	s.recordAudit(ctx, principal, call, "allowed", "")

	result, err := tool.Handle(ctx, call.Arguments)
	if err != nil {
		return ToolResult{IsError: true, ErrorMessage: err.Error()}
	}
	return result
}

func (s *Server) deny(ctx context.Context, principal Principal, call ToolCall, result, reason string) ToolResult {
	s.recordAudit(ctx, principal, call, result, reason)
	return ToolResult{IsError: true, ErrorMessage: reason}
}

func (s *Server) recordAudit(ctx context.Context, principal Principal, call ToolCall, result, reason string) {
	meta := map[string]string{"tool": call.Name}
	if reason != "" {
		meta["reason"] = reason
	}
	// Audit failures must never block or fail the dispatch decision
	// already made — the caller's allow/deny outcome is independent of
	// whether the audit write itself succeeded.
	_ = s.audit.Record(ctx, audit.Event{
		Actor:     principal.ID,
		Action:    "mcp:tool_call:" + call.Name,
		Resource:  call.Name,
		Result:    result,
		Timestamp: time.Now().UTC(),
		Metadata:  meta,
	})
}

func policyInputFor(tool Tool) policyengine.PolicyInput {
	attrs := map[string]string{"tool": tool.Name()}

	// policyengine.NativeEngine's mcp domain matches on
	// Attributes["scope"] against its MCPPolicy.Allow allowlist (see
	// internal/policyengine/native.go's evaluateMCP) — a tool's first
	// required scope is what that allowlist decision is actually about.
	// Tools declare exactly one required scope today; if that changes,
	// this needs to evaluate per-scope instead of taking [0].
	if scopes := tool.RequiredScopes(); len(scopes) > 0 {
		attrs["scope"] = string(scopes[0])
	}

	return policyengine.PolicyInput{
		Domain:     "mcp",
		Action:     "mcp:tool:" + tool.Name(),
		Attributes: attrs,
	}
}

func validateArguments(tool Tool, args map[string]any) string {
	allowed := make(map[string]bool, len(tool.AllowedArguments()))
	for _, a := range tool.AllowedArguments() {
		allowed[a] = true
	}
	for k := range args {
		if !allowed[k] {
			return fmt.Sprintf("tool %q does not accept argument %q", tool.Name(), k)
		}
	}
	return ""
}
