package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// TODO(sprint-4): back this by the API/storage layer once it exists.
// The CLI has no long-lived process to hold findings in between
// invocations, so `findings list/get` are only meaningful against a
// running `cerberus server` for now.
func newFindingsCmd(flags *globalFlags) *cobra.Command {
	findings := &cobra.Command{Use: "findings", Short: "Inspect stored findings (requires a running cerberus server)"}

	findings.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("findings list requires a running cerberus server (see Sprint 4); not implemented in CLI-only mode")
		},
	})
	findings.AddCommand(&cobra.Command{
		Use:   "get <id>",
		Short: "Get a single finding by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("findings get requires a running cerberus server (see Sprint 4); use `cerberus scan file --format explain` for offline use")
		},
	})

	return findings
}
