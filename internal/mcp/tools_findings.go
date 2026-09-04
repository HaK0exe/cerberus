package mcp

import (
	"context"
	"strconv"

	"github.com/HaK0exe/cerberus/internal/findings"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// ListFindingsTool implements cerberus_list_findings.
type ListFindingsTool struct {
	Store findings.Store
}

func (t *ListFindingsTool) Name() string            { return "cerberus_list_findings" }
func (t *ListFindingsTool) RequiredScopes() []Scope { return []Scope{ScopeFindingsRead} }
func (t *ListFindingsTool) AllowedArguments() []string {
	return []string{"state", "source_type", "rule_id", "limit"}
}

func (t *ListFindingsTool) Handle(ctx context.Context, args map[string]any) (ToolResult, error) {
	filter := findings.Filter{
		State:      cerberus.State(stringArg(args, "state")),
		SourceType: cerberus.SourceType(stringArg(args, "source_type")),
		RuleID:     stringArg(args, "rule_id"),
	}
	if v, ok := args["limit"]; ok {
		filter.Limit = intArg(v)
	}

	list, err := t.Store.List(ctx, filter)
	if err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Content: list}, nil
}

// GetFindingTool implements cerberus_get_finding.
type GetFindingTool struct {
	Store findings.Store
}

func (t *GetFindingTool) Name() string               { return "cerberus_get_finding" }
func (t *GetFindingTool) RequiredScopes() []Scope    { return []Scope{ScopeFindingsRead} }
func (t *GetFindingTool) AllowedArguments() []string { return []string{"finding_id"} }

func (t *GetFindingTool) Handle(ctx context.Context, args map[string]any) (ToolResult, error) {
	id := stringArg(args, "finding_id")
	if id == "" {
		return ToolResult{IsError: true, ErrorMessage: "finding_id is required"}, nil
	}
	f, err := t.Store.Get(ctx, id)
	if err != nil {
		return ToolResult{IsError: true, ErrorMessage: err.Error()}, nil
	}
	return ToolResult{Content: f}, nil
}

// ExplainFindingTool implements cerberus_explain_finding: the MCP
// equivalent of `cerberus scan file --format explain`. It returns the
// same DetectionProvenance a Finding already carries — never a
// separately-computed explanation, so the two surfaces can never drift
// apart.
type ExplainFindingTool struct {
	Store findings.Store
}

func (t *ExplainFindingTool) Name() string               { return "cerberus_explain_finding" }
func (t *ExplainFindingTool) RequiredScopes() []Scope    { return []Scope{ScopeFindingsRead} }
func (t *ExplainFindingTool) AllowedArguments() []string { return []string{"finding_id"} }

func (t *ExplainFindingTool) Handle(ctx context.Context, args map[string]any) (ToolResult, error) {
	id := stringArg(args, "finding_id")
	if id == "" {
		return ToolResult{IsError: true, ErrorMessage: "finding_id is required"}, nil
	}
	f, err := t.Store.Get(ctx, id)
	if err != nil {
		return ToolResult{IsError: true, ErrorMessage: err.Error()}, nil
	}
	return ToolResult{Content: f.Provenance}, nil
}

func stringArg(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return v
}

func intArg(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	default:
		return 0
	}
}
