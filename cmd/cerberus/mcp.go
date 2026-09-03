package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// TODO(sprint-4): start the cerberus-mcp server in-process (stdio mode)
// for local agent use; the standalone cmd/cerberus-mcp binary also
// supports HTTP mode for remote deployments.
func newMCPCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run the Cerberus MCP server (stdio)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("cerberus mcp is not implemented yet (see Sprint 4)")
		},
	}
}
