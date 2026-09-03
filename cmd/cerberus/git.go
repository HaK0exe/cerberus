package main

import (
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

			s := gitscanner.New()
			opts := cerberus.ScanOptions{History: history, Staged: staged, Branch: branch}
			_, err := s.Scan(cmd.Context(), gitscanner.Repository{Path: args[0], Mode: mode, Ref: ref}, opts)
			return err
		},
	}
	scan.Flags().BoolVar(&staged, "staged", false, "scan staged changes only")
	scan.Flags().BoolVar(&history, "history", false, "scan full commit history")
	scan.Flags().StringVar(&branch, "branch", "", "scan a specific branch")
	scan.Flags().StringVar(&commit, "commit", "", "scan a specific commit")

	git.AddCommand(scan)
	return git
}
