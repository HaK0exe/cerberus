// Package mcp implements the transport-agnostic core of the Cerberus
// MCP control-plane server: a fixed set of tools (read-only findings/
// credentials/incidents lookups, scan lifecycle, remediation
// request/execute) dispatched through one non-bypassable pipeline —
// Authentication (assumed already done upstream, by a future stdio/
// HTTP transport) → Authorization → Policy → Scope validation → Rate
// limiting → Audit → Execution. See Server.Dispatch.
//
// This package holds no transport and no privileged credentials:
// cerberus_execute_remediation runs through the exact same pipeline as
// every other tool and, today, performs no privileged action — see
// docs/adr/0009-mcp-v2.md and docs/adr/0003-remediation-separation.md.
package mcp

import "context"

// Scope is an explicit MCP permission. A Principal's GrantedScopes are
// the only source of truth Server.Dispatch consults for authorization
// — never anything a tool call claims about itself.
type Scope string

const (
	ScopeFindingsRead       Scope = "findings:read"
	ScopeCredentialsRead    Scope = "credentials:read"
	ScopeIncidentsRead      Scope = "incidents:read"
	ScopeScansRead          Scope = "scans:read"
	ScopeScansStart         Scope = "scans:start"
	ScopeScansCancel        Scope = "scans:cancel"
	ScopeRemediationRead    Scope = "remediation:read"
	ScopeRemediationRequest Scope = "remediation:request"
	ScopeRemediationExecute Scope = "remediation:execute"
)

// ToolCall is one inbound tool invocation, before Dispatch has run
// Authorization/Policy/etc.
//
// RequestedScopes is informational only (logging/debugging) and is
// never consulted for the authorization decision itself — only the
// authenticated Principal's GrantedScopes are (see Server.Dispatch). A
// caller cannot grant itself access by simply asking for a scope here;
// that is precisely the "never trust an agent because it knows a tool
// name/scope" invariant this package is built around.
type ToolCall struct {
	Name            string
	Arguments       map[string]any
	RequestedScopes []Scope
}

// ToolResult is a tool's response.
//
// Content must never contain a raw secret value. Every domain type it
// can carry (cerberus.Finding, cerberus.Credential, cerberus.Exposure,
// cerberus.Incident, cerberus.DetectionProvenance) already enforces
// that structurally (see ADR-0001) — a Tool implementation only has to
// pass those types through unchanged and must never reach into an
// Artifact/Candidate for a raw value.
type ToolResult struct {
	Content      any
	IsError      bool
	ErrorMessage string
}

// Tool is one MCP tool.
//
// RequiredScopes is enforced by Server.Dispatch, never by the Tool
// trusting its own caller. AllowedArguments lists every argument key
// Handle understands; Dispatch rejects any call carrying a key outside
// this list before Handle ever runs. Mutating tools must only ever
// declare ID-shaped arguments (finding_id, credential_id,
// incident_id, remediation_id) — never one that could carry a raw
// secret value.
type Tool interface {
	Name() string
	RequiredScopes() []Scope
	AllowedArguments() []string
	Handle(ctx context.Context, args map[string]any) (ToolResult, error)
}
