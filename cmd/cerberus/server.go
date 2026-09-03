package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// TODO(sprint-4): start the cerberus-api HTTP server in-process for
// local/dev use (the standalone cmd/cerberus-api binary is for
// container/Lambda deployment).
func newServerCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "server",
		Short: "Run the Cerberus API server locally",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("cerberus server is not implemented yet (see Sprint 4)")
		},
	}
}
