package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// TODO(sprint-5): wire to internal/remediation + internal/remediation/aws.
// remediation apply defaults to dry-run; --apply is required to execute
// for real, and even then execution requires an approved Plan.
func newRemediationCmd(flags *globalFlags) *cobra.Command {
	remediation := &cobra.Command{Use: "remediation", Short: "Plan and apply controlled remediation of compromised secrets"}

	remediation.AddCommand(&cobra.Command{
		Use:   "plan <finding-id>",
		Short: "Build a remediation plan for a finding (dry-run, no side effects)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("remediation planning is not implemented yet (see Sprint 5)")
		},
	})

	var apply bool
	applyCmd := &cobra.Command{
		Use:   "apply <plan-id>",
		Short: "Execute an approved remediation plan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !apply {
				return fmt.Errorf("dry-run only: pass --apply to execute (also requires an APPROVED plan)")
			}
			return fmt.Errorf("remediation execution is not implemented yet (see Sprint 5)")
		},
	}
	applyCmd.Flags().BoolVar(&apply, "apply", false, "actually execute the plan (default is dry-run)")
	remediation.AddCommand(applyCmd)

	return remediation
}
