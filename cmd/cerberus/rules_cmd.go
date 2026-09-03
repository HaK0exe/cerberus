package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/HaK0exe/cerberus/internal/detector"
	"github.com/HaK0exe/cerberus/internal/rules"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func newRulesCmd(flags *globalFlags) *cobra.Command {
	rulesCmd := &cobra.Command{Use: "rules", Short: "Inspect and test detection rules"}

	rulesCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List loaded rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			compiled, err := rules.LoadDir(os.DirFS("."), flags.rulesDir)
			if err != nil {
				return err
			}
			for _, r := range compiled {
				fmt.Printf("%-32s %-10s confidence=%.2f  %s\n", r.ID, r.Severity, r.Confidence, r.Name)
			}
			return nil
		},
	})

	rulesCmd.AddCommand(&cobra.Command{
		Use:   "test <rule-id> <sample-text>",
		Short: "Test a single rule against a sample string",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ruleID, sample := args[0], args[1]

			compiled, err := rules.LoadDir(os.DirFS("."), flags.rulesDir)
			if err != nil {
				return err
			}

			var matches []rules.CompiledRule
			for _, r := range compiled {
				if r.ID == ruleID {
					matches = append(matches, r)
				}
			}
			if len(matches) == 0 {
				return fmt.Errorf("rule %q not found in %s", ruleID, flags.rulesDir)
			}

			d, err := buildDetectorFromRules(matches)
			if err != nil {
				return err
			}

			findings, err := d.Detect(cmd.Context(), cerberus.Artifact{
				ID:         "test",
				SourceType: cerberus.SourceFile,
				Path:       "<inline>",
				Content:    []byte(sample),
			})
			if err != nil {
				return err
			}
			return renderFindings(flags.format, findings)
		},
	})

	return rulesCmd
}

func buildDetectorFromRules(compiled []rules.CompiledRule) (*detector.Detector, error) {
	return detector.New(compiled, nil, detector.WithMinEmitBand(detector.BandIgnore)), nil
}
