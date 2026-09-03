package main

import (
	"fmt"

	"github.com/spf13/cobra"

	gitscanner "github.com/HaK0exe/cerberus/internal/scanner/git"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func newGitCmd(flags *globalFlags) *cobra.Command {
	git := &cobra.Command{Use: "git", Short: "Git repository scanning"}

	var staged, history bool
	var branch, commit string

	scan := &cobra.Command{
		Use:   "scan <path>",
		Short: "Scan a Git repository (working tree, staged, commit, branch, or full history)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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

			d, err := buildDetector(flags.rulesDir)
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

			return renderFindings(flags.format, all)
		},
	}
	scan.Flags().BoolVar(&staged, "staged", false, "scan staged changes only")
	scan.Flags().BoolVar(&history, "history", false, "scan full commit history")
	scan.Flags().StringVar(&branch, "branch", "", "scan a specific branch")
	scan.Flags().StringVar(&commit, "commit", "", "scan a specific commit")

	git.AddCommand(scan)
	return git
}
