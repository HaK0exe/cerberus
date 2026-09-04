// Command cerberus-mcp is the standalone MCP server entrypoint: a
// minimal binary an MCP client config (Claude Desktop, Claude Code,
// etc.) can point its "command" at without pulling in the whole
// cerberus CLI surface. It wraps internal/mcpserve.Run — the same
// implementation behind `cerberus mcp serve`.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/HaK0exe/cerberus/internal/mcpserve"
	"github.com/HaK0exe/cerberus/internal/version"
)

type scopeList []string

func (s *scopeList) String() string { return strings.Join(*s, ",") }
func (s *scopeList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	var findingsPath, correlatePath, policyPath, auditPath, principalID string
	var rate, burst float64
	var scopes scopeList

	fs := flag.NewFlagSet("cerberus-mcp", flag.ExitOnError)
	fs.StringVar(&findingsPath, "findings", "", "path to a Findings JSON file to seed the findings store")
	fs.StringVar(&correlatePath, "correlate", "", "path to a `cerberus correlate --format json` document to seed the credentials/incidents stores")
	fs.StringVar(&policyPath, "policy", "", "path to a native policyengine YAML policy file (default: empty policy, default-deny)")
	fs.StringVar(&auditPath, "audit-log", "", "append-only JSONL audit log path (default: stderr)")
	fs.StringVar(&principalID, "principal", "mcp-client", "principal ID recorded in the audit trail for every call this process serves")
	fs.Var(&scopes, "scope", "scope granted to whatever client connects over stdio, repeatable (e.g. -scope findings:read); none by default (default-deny)")
	fs.Float64Var(&rate, "rate-limit", 5, "sustained tool calls per second allowed for this principal")
	fs.Float64Var(&burst, "burst", 10, "burst allowance of tool calls for this principal")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := mcpserve.Run(ctx, mcpserve.Options{
		FindingsPath:  findingsPath,
		CorrelatePath: correlatePath,
		PolicyPath:    policyPath,
		AuditPath:     auditPath,
		PrincipalID:   principalID,
		Scopes:        scopes,
		Rate:          rate,
		Burst:         burst,
		ServerName:    "cerberus-mcp",
		ServerVersion: version.Version,
		Stderr:        os.Stderr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cerberus-mcp: %v\n", err)
		os.Exit(1)
	}
}
