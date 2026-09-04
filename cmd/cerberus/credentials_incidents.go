package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// TODO(sprint-4): back these by the API/storage layer once it exists.
// The CLI has no long-lived process to hold correlated credentials and
// incidents in between invocations, so `credentials`/`incidents`
// list/get are only meaningful against a running `cerberus server` for
// now — see `cerberus correlate` for the offline, single-shot
// equivalent over a Findings JSON file.
func newCredentialsCmd(flags *globalFlags) *cobra.Command {
	credentials := &cobra.Command{Use: "credentials", Short: "Inspect correlated credentials (requires a running cerberus server)"}

	credentials.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List unique credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("credentials list requires a running cerberus server (see Sprint 4); use `cerberus correlate` for offline use")
		},
	})
	credentials.AddCommand(&cobra.Command{
		Use:   "get <id>",
		Short: "Get a single credential by ID, including its exposures",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("credentials get requires a running cerberus server (see Sprint 4); use `cerberus correlate` for offline use")
		},
	})

	return credentials
}

func newIncidentsCmd(flags *globalFlags) *cobra.Command {
	incidents := &cobra.Command{Use: "incidents", Short: "Inspect incidents (requires a running cerberus server)"}

	incidents.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List incidents",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("incidents list requires a running cerberus server (see Sprint 4); use `cerberus correlate` for offline use")
		},
	})
	incidents.AddCommand(&cobra.Command{
		Use:   "get <id>",
		Short: "Get a single incident by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("incidents get requires a running cerberus server (see Sprint 4); use `cerberus correlate` for offline use")
		},
	})

	return incidents
}
