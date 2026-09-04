package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/HaK0exe/cerberus/internal/policyengine"
	"github.com/HaK0exe/cerberus/internal/remediation"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// TODO(sprint-5): `remediation apply` stays a stub — internal/remediation/aws.Executor
// exists and is fully tested (see internal/remediation/aws/aws_test.go), but it
// takes an IAMClient this CLI has no real (non-fake) implementation to hand
// it: no AWS SDK dependency has been wired in yet (see docs/adr/0010-remediation-v2.md).
// `remediation plan` is real: it builds an actual, side-effect-free
// remediation.Plan via DefaultPlanner (risk + policy), which is as far as
// this codebase can honestly go without a privileged, provider-specific
// executor behind it.
func newRemediationCmd(flags *globalFlags) *cobra.Command {
	remediationCmd := &cobra.Command{Use: "remediation", Short: "Plan and apply controlled remediation of compromised secrets"}
	remediationCmd.AddCommand(newRemediationPlanCmd(flags))

	var apply bool
	applyCmd := &cobra.Command{
		Use:   "apply <plan-id>",
		Short: "Execute an approved remediation plan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !apply {
				return fmt.Errorf("dry-run only: pass --apply to execute (also requires an APPROVED plan)")
			}
			return fmt.Errorf("remediation execution has no real provider wired into the CLI yet: " +
				"internal/remediation/aws.Executor is implemented and tested against a fake IAMClient, " +
				"but no AWS SDK adapter exists to back it with a real one (see docs/adr/0010-remediation-v2.md)")
		},
	}
	applyCmd.Flags().BoolVar(&apply, "apply", false, "actually execute the plan (default is dry-run)")
	remediationCmd.AddCommand(applyCmd)

	return remediationCmd
}

// newRemediationPlanCmd wires internal/remediation.DefaultPlanner: given
// a single Credential + its Exposures (e.g. selected out of `cerberus
// correlate --format json` output via --credential-id) and a policy
// document (--policy, native YAML — see internal/policyengine), it
// builds a Plan. Building a Plan performs no side effect — see
// remediation.Plan's doc comment.
func newRemediationPlanCmd(flags *globalFlags) *cobra.Command {
	var input string
	var policyPath string
	var credentialID string
	var action string
	var environment string

	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Build a remediation plan for a credential (dry-run, no side effects)",
		Long: "Reads a `cerberus correlate --format json` document (from --input or\n" +
			"stdin), selects the credential named by --credential-id, assesses its\n" +
			"risk, evaluates the given policy document (--policy, native YAML — see\n" +
			"internal/policyengine), and prints the resulting remediation.Plan.\n" +
			"No policy file means default-deny: nothing is planned without an\n" +
			"explicit remediation policy.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if credentialID == "" {
				return fmt.Errorf("--credential-id is required")
			}
			if action == "" {
				return fmt.Errorf("--action is required (e.g. disable_access_key)")
			}

			var r io.Reader = os.Stdin
			if input != "" && input != "-" {
				f, err := os.Open(input) // #nosec G304 -- input is a --input path supplied on the CLI command line
				if err != nil {
					return fmt.Errorf("opening %s: %w", input, err)
				}
				defer f.Close()
				r = f
			}

			var doc correlationResult
			if err := json.NewDecoder(r).Decode(&doc); err != nil {
				return fmt.Errorf("decoding correlate JSON: %w", err)
			}

			var credential cerberus.Credential
			found := false
			for _, c := range doc.Credentials {
				if c.ID == credentialID {
					credential, found = c, true
					break
				}
			}
			if !found {
				return fmt.Errorf("credential %q not found in input", credentialID)
			}

			var exposures []cerberus.Exposure
			for _, e := range doc.Exposures {
				if e.CredentialID == credentialID {
					exposures = append(exposures, e)
				}
			}

			policy, err := loadRemediationPolicy(policyPath)
			if err != nil {
				return err
			}

			planner := remediation.NewPlanner(policyengine.NewNativeEngine(policy))
			plan, err := planner.Plan(cmd.Context(), credential, exposures, action, environment)
			if err != nil {
				return err
			}

			return renderPlan(flags.format, plan)
		},
	}

	cmd.Flags().StringVar(&input, "input", "-", "path to a `cerberus correlate --format json` document (default: stdin)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "path to a native policyengine YAML policy file (default: empty policy, default-deny)")
	cmd.Flags().StringVar(&credentialID, "credential-id", "", "which credential in the input to plan for (required)")
	cmd.Flags().StringVar(&action, "action", "", "provider-specific remediation action, e.g. disable_access_key (required)")
	cmd.Flags().StringVar(&environment, "environment", "", "environment the credential belongs to, e.g. production|development (matched by the remediation policy)")
	return cmd
}

func loadRemediationPolicy(path string) (policyengine.Policy, error) {
	if path == "" {
		return policyengine.Policy{}, nil // zero-value Policy: NativeEngine default-denies everything
	}
	f, err := os.Open(path) // #nosec G304 -- path is a --policy path supplied on the CLI command line
	if err != nil {
		return policyengine.Policy{}, fmt.Errorf("opening policy file %s: %w", path, err)
	}
	defer f.Close()

	p, err := policyengine.LoadYAML(f)
	if err != nil {
		return policyengine.Policy{}, err
	}
	return p, nil
}

func renderPlan(format string, plan remediation.Plan) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(plan)
	case "text", "":
		fmt.Printf("%s  %s/%s  action=%s  status=%s\n", plan.ID, plan.Provider, plan.CredentialID, plan.Action, plan.Status)
		fmt.Printf("  risk:      %s (%.2f)\n", plan.Risk.Level, plan.Risk.Score)
		if plan.ApprovalRequired {
			fmt.Printf("  approvals: %d/%d required\n", plan.ApprovalsGranted, plan.ApprovalsRequired)
		}
		fmt.Printf("  reason:    %s\n", plan.Reason)
		return nil
	default:
		return fmt.Errorf("unknown format %q (want json|text)", format)
	}
}
