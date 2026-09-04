package mcp

import "context"

// RequestRemediationTool implements cerberus_request_remediation. It
// only ever accepts a credential_id — never a secret value.
//
// Building a real Plan requires resolving a credential to a Finding
// (internal/remediation.Planner.Plan takes a finding ID today, not a
// credential ID) plus a wired Planner implementation; neither exists
// yet beyond the AWS package scaffold. Rather than fabricate a Plan
// this package has no authority to back, Handle returns an honest
// "not available" result — see internal/remediation and Phase K.
type RequestRemediationTool struct{}

func (t *RequestRemediationTool) Name() string            { return "cerberus_request_remediation" }
func (t *RequestRemediationTool) RequiredScopes() []Scope { return []Scope{ScopeRemediationRequest} }
func (t *RequestRemediationTool) AllowedArguments() []string {
	return []string{"credential_id"}
}

func (t *RequestRemediationTool) Handle(ctx context.Context, args map[string]any) (ToolResult, error) {
	id := stringArg(args, "credential_id")
	if id == "" {
		return ToolResult{IsError: true, ErrorMessage: "credential_id is required"}, nil
	}
	return ToolResult{
		IsError:      true,
		ErrorMessage: "remediation planning is not wired yet: no Planner is available for credential " + id + " (see Phase K)",
	}, nil
}

// ExecuteRemediationTool implements cerberus_execute_remediation — the
// privileged tool the Dispatch pipeline exists for (see
// docs/adr/0009-mcp-v2.md).
//
// It performs NO privileged action today: this package holds no cloud
// credentials, and no approved Plan/Executor is wired in yet (Phase
// K). It exists now so the pipeline (scope check → policy → audit) is
// exercised on the exact tool that will eventually reach
// internal/remediation, rather than bolted on later under pressure —
// see docs/adr/0003-remediation-separation.md.
type ExecuteRemediationTool struct{}

func (t *ExecuteRemediationTool) Name() string            { return "cerberus_execute_remediation" }
func (t *ExecuteRemediationTool) RequiredScopes() []Scope { return []Scope{ScopeRemediationExecute} }
func (t *ExecuteRemediationTool) AllowedArguments() []string {
	return []string{"remediation_id"}
}

func (t *ExecuteRemediationTool) Handle(ctx context.Context, args map[string]any) (ToolResult, error) {
	id := stringArg(args, "remediation_id")
	if id == "" {
		return ToolResult{IsError: true, ErrorMessage: "remediation_id is required"}, nil
	}
	return ToolResult{
		IsError: true,
		ErrorMessage: "remediation execution is not wired yet: no approved plan or Executor is available for remediation " +
			id + " (see Phase K, docs/adr/0003-remediation-separation.md)",
	}, nil
}
