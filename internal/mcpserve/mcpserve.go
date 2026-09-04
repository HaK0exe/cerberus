// Package mcpserve wires internal/mcp.Server onto a real stdio MCP
// transport (github.com/modelcontextprotocol/go-sdk). It is the
// shared implementation behind both `cerberus mcp serve` and the
// standalone cerberus-mcp binary (cmd/cerberus-mcp) — the two ways an
// MCP client (Claude Code, Claude Desktop, or any other MCP-compatible
// host) can launch a Cerberus control-plane server.
//
// This package holds no privileged credentials and authenticates
// nothing itself: the launching client is trusted with exactly the
// scopes Options.Scopes grants for the lifetime of the process. See
// internal/mcp's package doc for the pipeline this transport sits on
// top of, and docs/adr/0009-mcp-v2.md for the overall design.
package mcpserve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HaK0exe/cerberus/internal/audit"
	"github.com/HaK0exe/cerberus/internal/credentials"
	"github.com/HaK0exe/cerberus/internal/findings"
	"github.com/HaK0exe/cerberus/internal/mcp"
	"github.com/HaK0exe/cerberus/internal/policyengine"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// Options configures one Cerberus MCP stdio server process.
type Options struct {
	// FindingsPath, if set, is a Findings JSON file used to seed the
	// findings store served to the connecting client.
	FindingsPath string
	// CorrelatePath, if set, is a `cerberus correlate --format json`
	// document used to seed the credentials/exposures/incidents store.
	CorrelatePath string
	// PolicyPath is a native policyengine YAML policy file. Empty
	// means the zero-value Policy, which default-denies everything.
	PolicyPath string
	// AuditPath is an append-only JSONL audit log path. Empty means
	// audit events go to Stderr instead — this package never silently
	// discards audit events (never audit.NopSink) in Run.
	AuditPath string
	// PrincipalID is recorded in the audit trail for every call this
	// process serves.
	PrincipalID string
	// Scopes are granted, for the process lifetime, to whatever client
	// connects over stdio. Nil/empty means default-deny.
	Scopes []string
	// Rate and Burst configure the per-principal rate limiter.
	Rate  float64
	Burst float64
	// ServerName/ServerVersion identify this process to the connecting
	// MCP client during initialize.
	ServerName    string
	ServerVersion string
	// Stderr receives diagnostics (and the audit trail, if AuditPath is
	// empty). Defaults to os.Stderr if nil.
	Stderr io.Writer
}

// Run seeds the findings/credentials stores and policy from opts,
// builds an internal/mcp.Server, registers every tool it exposes onto
// an MCP stdio server, and blocks serving requests until ctx is
// canceled or the client disconnects.
func Run(ctx context.Context, opts Options) error {
	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	findingsStore := findings.NewMemStore()
	if opts.FindingsPath != "" {
		if err := loadFindingsInto(ctx, findingsStore, opts.FindingsPath); err != nil {
			return err
		}
	}

	credStore := credentials.NewMemStore()
	if opts.CorrelatePath != "" {
		if err := loadCorrelationInto(ctx, credStore, opts.CorrelatePath); err != nil {
			return err
		}
	}

	policy, err := loadRemediationPolicy(opts.PolicyPath)
	if err != nil {
		return err
	}

	sink, closeSink, err := buildAuditSink(opts.AuditPath, stderr)
	if err != nil {
		return err
	}
	defer closeSink()

	tools := BuildTools(findingsStore, credStore)
	server := mcp.NewServer(
		policyengine.NewNativeEngine(policy),
		mcp.NewRateLimiter(opts.Rate, opts.Burst),
		sink,
		tools...,
	)
	principal := mcp.Principal{ID: opts.PrincipalID, GrantedScopes: toScopes(opts.Scopes)}

	name := opts.ServerName
	if name == "" {
		name = "cerberus"
	}
	sdkServer := sdkmcp.NewServer(&sdkmcp.Implementation{
		Name:    name,
		Version: opts.ServerVersion,
	}, nil)
	for _, t := range tools {
		sdkServer.AddTool(sdkToolFor(t), dispatchHandler(server, principal, t.Name()))
	}

	fmt.Fprintf(stderr, "%s: listening on stdio (principal=%q scopes=%v, %d tools)\n",
		name, opts.PrincipalID, opts.Scopes, len(tools))
	return sdkServer.Run(ctx, &sdkmcp.StdioTransport{})
}

// BuildTools returns every tool internal/mcp implements, wired to the
// given stores. StartScanTool/CancelScanTool/GetScanTool/
// RequestRemediationTool/ExecuteRemediationTool hold no store — they
// are the honest stubs documented in docs/adr/0009-mcp-v2.md.
func BuildTools(findingsStore findings.Store, credStore *credentials.MemStore) []mcp.Tool {
	return []mcp.Tool{
		&mcp.ListFindingsTool{Store: findingsStore},
		&mcp.GetFindingTool{Store: findingsStore},
		&mcp.ExplainFindingTool{Store: findingsStore},
		&mcp.ListCredentialsTool{Store: credStore},
		&mcp.GetCredentialTool{Store: credStore},
		&mcp.ListIncidentsTool{Store: credStore},
		&mcp.GetIncidentTool{Store: credStore},
		&mcp.StartScanTool{},
		&mcp.CancelScanTool{},
		&mcp.GetScanTool{},
		&mcp.RequestRemediationTool{},
		&mcp.ExecuteRemediationTool{},
	}
}

// buildAuditSink opens path as a FileSink, or — if path is empty —
// wraps stderr, so Run always has a real, non-discarding audit trail
// by default (never audit.NopSink, per internal/audit's own doc
// comment). The returned close func is safe to call unconditionally.
func buildAuditSink(path string, stderr io.Writer) (*audit.FileSink, func(), error) {
	if path == "" {
		return audit.NewFileSink(stderr), func() {}, nil
	}
	sink, err := audit.OpenFileSink(path)
	if err != nil {
		return nil, nil, err
	}
	return sink, func() { _ = sink.Close() }, nil
}

// sdkToolFor translates one internal/mcp.Tool into the SDK's wire
// description. The input schema is deliberately permissive (an open
// "object") — internal/mcp.Server.Dispatch, not the transport, is the
// enforcement point for which argument keys a tool actually accepts
// (see validateArguments in internal/mcp/server.go), so the schema
// here exists only to satisfy the SDK's requirement that every tool
// declare one.
func sdkToolFor(t mcp.Tool) *sdkmcp.Tool {
	scopeNames := make([]string, len(t.RequiredScopes()))
	for i, s := range t.RequiredScopes() {
		scopeNames[i] = string(s)
	}
	desc := fmt.Sprintf("requires scope(s): %s; accepts argument(s): %s",
		strings.Join(scopeNames, ","), strings.Join(t.AllowedArguments(), ","))
	return &sdkmcp.Tool{
		Name:        t.Name(),
		Description: desc,
		InputSchema: &sdkJSONSchemaObject,
	}
}

// dispatchHandler adapts one internal/mcp.Tool's SDK-facing
// ToolHandler to run through mcp.Server.Dispatch — the same
// Authorization → Policy → Scope validation → Rate limiting → Audit →
// Execution pipeline `cerberus mcp call` exercises offline.
func dispatchHandler(server *mcp.Server, principal mcp.Principal, toolName string) sdkmcp.ToolHandler {
	return func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		var args map[string]any
		if len(req.Params.Arguments) > 0 {
			if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
				return nil, fmt.Errorf("invalid arguments for %s: %w", toolName, err)
			}
		}

		result := server.Dispatch(ctx, principal, mcp.ToolCall{Name: toolName, Arguments: args})
		return toSDKResult(result)
	}
}

// toSDKResult renders an internal/mcp.ToolResult as an MCP
// CallToolResult. Per the SDK's own convention, a tool-level error
// (denied/failed) is reported as IsError=true content text, not a
// protocol-level Go error, so the calling model can see and react to
// it instead of the transport just failing the request.
func toSDKResult(result mcp.ToolResult) (*sdkmcp.CallToolResult, error) {
	if result.IsError {
		return &sdkmcp.CallToolResult{
			IsError: true,
			Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: result.ErrorMessage}},
		}, nil
	}

	body, err := json.MarshalIndent(result.Content, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding result: %w", err)
	}
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: string(body)}},
	}, nil
}

// sdkJSONSchemaObject is the shared permissive "any object" input
// schema handed to every tool registered in Run — see sdkToolFor.
var sdkJSONSchemaObject = jsonschema.Schema{Type: "object"}

func toScopes(names []string) []mcp.Scope {
	if len(names) == 0 {
		return nil
	}
	out := make([]mcp.Scope, len(names))
	for i, n := range names {
		out[i] = mcp.Scope(n)
	}
	return out
}

func loadFindingsInto(ctx context.Context, store *findings.MemStore, path string) error {
	f, err := os.Open(path) // #nosec G304 -- path is an operator-supplied findings file
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var list []cerberus.Finding
	if err := json.NewDecoder(f).Decode(&list); err != nil {
		return fmt.Errorf("decoding findings JSON: %w", err)
	}
	for _, fnd := range list {
		if err := store.Put(ctx, fnd); err != nil {
			return err
		}
	}
	return nil
}

// correlationDoc mirrors the JSON shape `cerberus correlate --format
// json` writes (see cmd/cerberus/correlate.go's correlationResult) —
// duplicated here rather than imported, since that type lives in
// package main and this package must not depend on cmd/cerberus.
type correlationDoc struct {
	Credentials []cerberus.Credential `json:"credentials"`
	Exposures   []cerberus.Exposure   `json:"exposures"`
	Incidents   []cerberus.Incident   `json:"incidents"`
}

func loadCorrelationInto(ctx context.Context, store *credentials.MemStore, path string) error {
	f, err := os.Open(path) // #nosec G304 -- path is an operator-supplied correlation file
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var doc correlationDoc
	if err := json.NewDecoder(f).Decode(&doc); err != nil {
		return fmt.Errorf("decoding correlate JSON: %w", err)
	}
	return store.PutAll(ctx, doc.Credentials, doc.Exposures, doc.Incidents)
}

func loadRemediationPolicy(path string) (policyengine.Policy, error) {
	if path == "" {
		return policyengine.Policy{}, nil // zero-value Policy: NativeEngine default-denies everything
	}
	f, err := os.Open(path) // #nosec G304 -- path is an operator-supplied policy file
	if err != nil {
		return policyengine.Policy{}, fmt.Errorf("opening policy file %s: %w", path, err)
	}
	defer f.Close()

	return policyengine.LoadYAML(f)
}
