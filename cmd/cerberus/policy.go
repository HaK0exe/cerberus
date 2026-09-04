package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/HaK0exe/cerberus/internal/policyengine"
)

// newPolicyCmd wires internal/policyengine.NativeEngine directly, so a
// policy document (see internal/policyengine/native.go's Policy schema
// and testdata/policy/example.yaml) can be exercised offline before
// it's wired into remediation/MCP/scan enforcement.
func newPolicyCmd(flags *globalFlags) *cobra.Command {
	policyCmd := &cobra.Command{Use: "policy", Short: "Evaluate policy decisions (internal/policyengine)"}
	policyCmd.AddCommand(newPolicyEvalCmd(flags))
	return policyCmd
}

func newPolicyEvalCmd(flags *globalFlags) *cobra.Command {
	var policyPath string
	var domain string
	var action string
	var environment string
	var attrs []string

	cmd := &cobra.Command{
		Use:   "eval",
		Short: "Evaluate a PolicyInput against a native YAML policy document",
		Long: "Loads --policy (native policyengine YAML — see\n" +
			"internal/policyengine/native.go and testdata/policy/example.yaml),\n" +
			"builds a PolicyInput from --domain/--action/--environment/--attr,\n" +
			"and prints the resulting PolicyDecision. No --policy means an empty\n" +
			"policy document: NativeEngine default-denies everything against it.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if domain == "" {
				return fmt.Errorf("--domain is required (e.g. remediation|mcp|scan)")
			}

			policy, err := loadRemediationPolicy(policyPath) // shared with `remediation plan`, same loader
			if err != nil {
				return err
			}

			attributes, err := parseAttrs(attrs)
			if err != nil {
				return err
			}

			engine := policyengine.NewNativeEngine(policy)
			decision, err := engine.Evaluate(cmd.Context(), policyengine.PolicyInput{
				Domain:      domain,
				Action:      action,
				Environment: environment,
				Attributes:  attributes,
			})
			if err != nil {
				return err
			}

			return renderPolicyDecision(flags.format, decision)
		},
	}

	cmd.Flags().StringVar(&policyPath, "policy", "", "path to a native policyengine YAML policy file (default: empty policy, default-deny)")
	cmd.Flags().StringVar(&domain, "domain", "", "policy domain: remediation|mcp|scan (required)")
	cmd.Flags().StringVar(&action, "action", "", "action being evaluated within the domain")
	cmd.Flags().StringVar(&environment, "environment", "", "environment, e.g. production|development (remediation domain)")
	cmd.Flags().StringArrayVar(&attrs, "attr", nil, "attribute key=value, repeatable (e.g. --attr provider=aws --attr scope=findings:read)")
	return cmd
}

func parseAttrs(attrs []string) (map[string]string, error) {
	if len(attrs) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(attrs))
	for _, a := range attrs {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			return nil, fmt.Errorf("invalid --attr %q: want key=value", a)
		}
		out[k] = v
	}
	return out, nil
}

func renderPolicyDecision(format string, decision policyengine.PolicyDecision) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(decision)
	case "text", "":
		fmt.Printf("allow: %v\n", decision.Allow)
		if decision.ApprovalsRequired > 0 {
			fmt.Printf("approvals_required: %d\n", decision.ApprovalsRequired)
		}
		fmt.Printf("reason: %s\n", decision.Reason)
		return nil
	default:
		return fmt.Errorf("unknown format %q (want json|text)", format)
	}
}
