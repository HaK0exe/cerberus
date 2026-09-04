package main

import (
	"fmt"

	"github.com/spf13/cobra"

	gitscanner "github.com/HaK0exe/cerberus/internal/scanner/git"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func newGitCmd(flags *globalFlags) *cobra.Command {
	git := &cobra.Command{Use: "git", Short: "Git repository scanning"}

	var staged, history, unmask bool
	var branch, commit, failOn string

	scan := &cobra.Command{
		Use:     "scan <path>",
		Short:   "Scan a Git repository (working tree, staged, commit, branch, or full history)",
		Example: "  cerberus git scan . --history\n  cerberus git scan . --branch main --format sarif\n  cerberus git scan . --staged --fail-on high  # pre-commit gate",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			failOnSeverity, err := parseFailOn(failOn)
			if err != nil {
				return err
			}

			mode := gitscanner.ModeWorkingTree
			ref := ""
			switch {
			case history:
				mode = gitscanner.ModeFullHistory
			case staged:
				mode = gitscanner.ModeStaged
			case commit != "":
				mode, ref = gitscanner.ModeCommit, commit
			case branch != "":
				mode, ref = gitscanner.ModeBranch, branch
			}

			warnUnmask(flags.UI(), unmask)

			d, err := buildDetector(flags.rulesDir, nil, unmask)
			if err != nil {
				return err
			}

			s := gitscanner.New()
			artifacts, err := s.Scan(cmd.Context(), gitscanner.Repository{Path: args[0], Mode: mode, Ref: ref}, cerberus.ScanOptions{
				History: history,
				Staged:  staged,
				Branch:  branch,
			})
			if err != nil {
				return fmt.Errorf("scanning %s: %w", args[0], err)
			}

			var all []cerberus.Finding
			for artifact := range artifacts {
				findings, err := d.Detect(cmd.Context(), artifact)
				if err != nil {
					return fmt.Errorf("scanning %s: %w", artifact.Path, err)
				}
				all = append(all, findings...)
			}

			if err := renderFindings(flags.UI(), flags.format, all); err != nil {
				return err
			}
			return checkFailOn(all, failOnSeverity)
		},
	}
	scan.Flags().BoolVar(&staged, "staged", false, "scan staged changes only")
	scan.Flags().BoolVar(&history, "history", false, "scan full commit history")
	scan.Flags().StringVar(&branch, "branch", "", "scan a specific branch")
	scan.Flags().StringVar(&commit, "commit", "", "scan a specific commit")
	scan.Flags().BoolVar(&unmask, "unmask", false, "print full secret values instead of a masked hint (local triage only — never use in CI/logs)")
	scan.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero if any finding is at or above this severity: critical|high|medium|low (default: never fail, exit 0) — for CI/git-hook gating")

	git.AddCommand(scan)
	git.AddCommand(newGitInstallHookCmd(flags))
	return git
}
