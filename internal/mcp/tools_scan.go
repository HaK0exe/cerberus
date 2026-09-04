package mcp

import "context"

// StartScanTool implements cerberus_start_scan.
//
// No scan-run orchestration or persistence exists yet — internal/queue
// is a bare publish/consume primitive with no job-run store, and there
// is no scan-run ID anything could track. Rather than fabricate a scan
// ID nothing backs, this returns an honest "not implemented" result.
type StartScanTool struct{}

func (t *StartScanTool) Name() string            { return "cerberus_start_scan" }
func (t *StartScanTool) RequiredScopes() []Scope { return []Scope{ScopeScansStart} }
func (t *StartScanTool) AllowedArguments() []string {
	return []string{"source_type", "target"}
}

func (t *StartScanTool) Handle(ctx context.Context, args map[string]any) (ToolResult, error) {
	return ToolResult{
		IsError:      true,
		ErrorMessage: "scan orchestration is not implemented yet: no scan-run store exists (see internal/queue, internal/storage)",
	}, nil
}

// CancelScanTool implements cerberus_cancel_scan. See StartScanTool —
// the same "no scan-run store" gap applies.
type CancelScanTool struct{}

func (t *CancelScanTool) Name() string               { return "cerberus_cancel_scan" }
func (t *CancelScanTool) RequiredScopes() []Scope    { return []Scope{ScopeScansCancel} }
func (t *CancelScanTool) AllowedArguments() []string { return []string{"scan_id"} }

func (t *CancelScanTool) Handle(ctx context.Context, args map[string]any) (ToolResult, error) {
	return ToolResult{
		IsError:      true,
		ErrorMessage: "scan orchestration is not implemented yet: no scan-run store exists (see internal/queue, internal/storage)",
	}, nil
}

// GetScanTool implements cerberus_get_scan. See StartScanTool — the
// same "no scan-run store" gap applies.
type GetScanTool struct{}

func (t *GetScanTool) Name() string               { return "cerberus_get_scan" }
func (t *GetScanTool) RequiredScopes() []Scope    { return []Scope{ScopeScansRead} }
func (t *GetScanTool) AllowedArguments() []string { return []string{"scan_id"} }

func (t *GetScanTool) Handle(ctx context.Context, args map[string]any) (ToolResult, error) {
	return ToolResult{
		IsError:      true,
		ErrorMessage: "scan orchestration is not implemented yet: no scan-run store exists (see internal/queue, internal/storage)",
	}, nil
}
