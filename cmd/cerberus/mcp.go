package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/HaK0exe/cerberus/internal/audit"
	"github.com/HaK0exe/cerberus/internal/credentials"
	"github.com/HaK0exe/cerberus/internal/findings"
	"github.com/HaK0exe/cerberus/internal/mcp"
	"github.com/HaK0exe/cerberus/internal/mcpserve"
	"github.com/HaK0exe/cerberus/internal/policyengine"
	"github.com/HaK0exe/cerberus/internal/version"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// newMCPCmd exercises internal/mcp — a real, tested tool-dispatch
// pipeline (Authorization → Policy → Scope validation → Rate limiting
// → Audit → Execution). `serve` runs it behind a real stdio transport
// (internal/mcpserve); `tools` and `call` run it offline, in-process,
// for inspection and scripting.
func newMCPCmd(flags *globalFlags) *cobra.Command {
	mcpCmd := &cobra.Command{Use: "mcp", Short: "Inspect and run the Cerberus MCP control-plane server (internal/mcp)"}
	mcpCmd.AddCommand(newMCPServeCmd(flags))
	mcpCmd.AddCommand(newMCPToolsCmd(flags))
	mcpCmd.AddCommand(newMCPCallCmd(flags))
	return mcpCmd
}

// newMCPServeCmd wires internal/mcpserve.Run's stdio transport into
// the CLI. See internal/mcpserve's package doc for what it does and
// docs/adr/0009-mcp-v2.md for the overall design. This is the CLI-
// embedded way to run the server; cmd/cerberus-mcp is the standalone-
// binary equivalent for MCP client configs that want to launch just
// the server, not the whole cerberus CLI surface.
func newMCPServeCmd(flags *globalFlags) *cobra.Command {
	var findingsPath string
	var correlatePath string
	var policyPath string
	var auditPath string
	var principalID string
	var scopes []string
	var rate, burst float64

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the Cerberus MCP server over stdio for a connecting MCP client",
		Long: "Serves internal/mcp's tool pipeline to an MCP client (Claude Code,\n" +
			"Claude Desktop, or any MCP-compatible host) over stdio.\n\n" +
			"All MCP protocol frames go to stdout — never print anything else\n" +
			"there. Diagnostics go to stderr. The granted scopes (--scope) are\n" +
			"fixed for the process lifetime: this command does not authenticate\n" +
			"per-request callers, so only run it in a context where the launching\n" +
			"client is itself trusted with exactly those scopes (see --scope).",
		Example: "  cerberus mcp serve --scope findings:read --scope credentials:read\n" +
			"  cerberus mcp serve --findings findings.json --correlate correlate.json --scope findings:read",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return mcpserve.Run(cmd.Context(), mcpserve.Options{
				FindingsPath:  findingsPath,
				CorrelatePath: correlatePath,
				PolicyPath:    policyPath,
				AuditPath:     auditPath,
				PrincipalID:   principalID,
				Scopes:        scopes,
				Rate:          rate,
				Burst:         burst,
				ServerName:    "cerberus",
				ServerVersion: version.Version,
				Stderr:        os.Stderr,
			})
		},
	}

	cmd.Flags().StringVar(&findingsPath, "findings", "", "path to a Findings JSON file to seed the findings store")
	cmd.Flags().StringVar(&correlatePath, "correlate", "", "path to a `cerberus correlate --format json` document to seed the credentials/incidents stores")
	cmd.Flags().StringVar(&policyPath, "policy", "", "path to a native policyengine YAML policy file (default: empty policy, default-deny)")
	cmd.Flags().StringVar(&auditPath, "audit-log", "", "append-only JSONL audit log path (default: stderr)")
	cmd.Flags().StringVar(&principalID, "principal", "mcp-client", "principal ID recorded in the audit trail for every call this process serves")
	cmd.Flags().StringArrayVar(&scopes, "scope", nil, "scope granted to whatever client connects over stdio, repeatable (e.g. --scope findings:read); none by default (default-deny)")
	cmd.Flags().Float64Var(&rate, "rate-limit", 5, "sustained tool calls per second allowed for this principal")
	cmd.Flags().Float64Var(&burst, "burst", 10, "burst allowance of tool calls for this principal")
	return cmd
}

func newMCPToolsCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "tools",
		Short: "List the MCP tools this server exposes, with their required scopes and arguments",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, t := range mcpserve.BuildTools(findings.NewMemStore(), credentials.NewMemStore()) {
				scopeNames := make([]string, len(t.RequiredScopes()))
				for i, s := range t.RequiredScopes() {
					scopeNames[i] = string(s)
				}
				fmt.Printf("%-30s scopes=%-24s args=%s\n",
					t.Name(), strings.Join(scopeNames, ","), strings.Join(t.AllowedArguments(), ","))
			}
			return nil
		},
	}
}

// newMCPCallCmd dispatches a single ToolCall through the real
// internal/mcp.Server pipeline, in-process, against in-memory stores
// seeded from local files — the offline equivalent of what
// `cerberus mcp serve` does per inbound request.
func newMCPCallCmd(flags *globalFlags) *cobra.Command {
	var toolName string
	var findingsPath string
	var correlatePath string
	var policyPath string
	var principalID string
	var scopes []string
	var toolArgs []string

	cmd := &cobra.Command{
		Use:   "call",
		Short: "Dispatch a single MCP tool call offline, through the full auth/policy/audit pipeline",
		Long: "Loads findings (--findings, a Findings JSON file) and/or a\n" +
			"`cerberus correlate --format json` document (--correlate) into\n" +
			"in-memory stores, builds a Principal from --principal/--scope, and\n" +
			"runs one ToolCall through internal/mcp.Server.Dispatch — the exact\n" +
			"pipeline `cerberus mcp serve` uses per request.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if toolName == "" {
				return fmt.Errorf("--tool is required")
			}

			ctx := cmd.Context()

			findingsStore := findings.NewMemStore()
			if findingsPath != "" {
				if err := loadFindingsInto(ctx, findingsStore, findingsPath); err != nil {
					return err
				}
			}

			credStore := credentials.NewMemStore()
			if correlatePath != "" {
				if err := loadCorrelationInto(ctx, credStore, correlatePath); err != nil {
					return err
				}
			}

			policy, err := loadRemediationPolicy(policyPath)
			if err != nil {
				return err
			}

			args, err := parseToolArgs(toolArgs)
			if err != nil {
				return err
			}

			server := mcp.NewServer(
				policyengine.NewNativeEngine(policy),
				mcp.NewRateLimiter(10, 10),
				audit.NopSink{},
				mcpserve.BuildTools(findingsStore, credStore)...,
			)

			principal := mcp.Principal{ID: principalID, GrantedScopes: toScopes(scopes)}
			result := server.Dispatch(ctx, principal, mcp.ToolCall{Name: toolName, Arguments: args})

			return renderToolResult(flags.format, result)
		},
	}

	cmd.Flags().StringVar(&toolName, "tool", "", "tool name, e.g. cerberus_get_finding (required)")
	cmd.Flags().StringVar(&findingsPath, "findings", "", "path to a Findings JSON file to seed the findings store")
	cmd.Flags().StringVar(&correlatePath, "correlate", "", "path to a `cerberus correlate --format json` document to seed the credentials/incidents stores")
	cmd.Flags().StringVar(&policyPath, "policy", "", "path to a native policyengine YAML policy file (default: empty policy, default-deny)")
	cmd.Flags().StringVar(&principalID, "principal", "cli", "principal ID recorded in the audit trail")
	cmd.Flags().StringArrayVar(&scopes, "scope", nil, "granted scope, repeatable (e.g. --scope findings:read)")
	cmd.Flags().StringArrayVar(&toolArgs, "arg", nil, "tool argument key=value, repeatable")
	return cmd
}

func loadFindingsInto(ctx context.Context, store *findings.MemStore, path string) error {
	f, err := os.Open(path)
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

func loadCorrelationInto(ctx context.Context, store *credentials.MemStore, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var doc correlationResult
	if err := json.NewDecoder(f).Decode(&doc); err != nil {
		return fmt.Errorf("decoding correlate JSON: %w", err)
	}
	return store.PutAll(ctx, doc.Credentials, doc.Exposures, doc.Incidents)
}

func parseToolArgs(pairs []string) (map[string]any, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(pairs))
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return nil, fmt.Errorf("invalid --arg %q: want key=value", p)
		}
		out[k] = v
	}
	return out, nil
}

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

func renderToolResult(format string, result mcp.ToolResult) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	case "text", "":
		if result.IsError {
			fmt.Printf("error: %s\n", result.ErrorMessage)
			return nil
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result.Content)
	default:
		return fmt.Errorf("unknown format %q (want json|text)", format)
	}
}
