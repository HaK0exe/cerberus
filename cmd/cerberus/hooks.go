package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// hookMarker identifies a pre-commit hook file this command wrote, so
// a later run can safely overwrite its own hook (e.g. to change
// --fail-on) without --force, while still refusing to clobber a
// hook it didn't install.
const hookMarker = "# installed-by: cerberus git install-hook"

func newGitInstallHookCmd(flags *globalFlags) *cobra.Command {
	var failOn string
	var force bool

	cmd := &cobra.Command{
		Use:   "install-hook",
		Short: "Install a git pre-commit hook that blocks commits containing secrets",
		Long: "Writes a pre-commit hook into this repository's hooks directory\n" +
			"(resolved via `git rev-parse --git-path hooks`, so it works with\n" +
			"worktrees and a custom core.hooksPath) that runs\n" +
			"`cerberus git scan . --staged --fail-on <severity>` before every\n" +
			"commit, aborting it if a finding at or above that severity is\n" +
			"staged. Requires `cerberus` to be on $PATH at commit time (see\n" +
			"`make install`).",
		Example: "  cerberus git install-hook\n  cerberus git install-hook --fail-on critical --force",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := parseFailOn(failOn); err != nil {
				return err
			}

			hooksDir, err := gitHooksDir()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(hooksDir, 0o755); err != nil {
				return fmt.Errorf("creating hooks directory %s: %w", hooksDir, err)
			}

			path := filepath.Join(hooksDir, "pre-commit")
			if existing, err := os.ReadFile(path); err == nil && !force {
				if !bytes.Contains(existing, []byte(hookMarker)) {
					return fmt.Errorf("%s already exists and was not installed by cerberus — rerun with --force to overwrite it", path)
				}
			}

			script := preCommitHookScript(failOn)
			if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
				return fmt.Errorf("writing %s: %w", path, err)
			}

			flags.UI().Infof("installed pre-commit hook at %s (fail-on=%s)", path, failOn)
			return nil
		},
	}

	cmd.Flags().StringVar(&failOn, "fail-on", "high", "block a commit if a staged finding is at or above this severity: critical|high|medium|low")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing pre-commit hook, even one cerberus didn't install")
	return cmd
}

// gitHooksDir resolves the repository's hooks directory the way git
// itself would (respects core.hooksPath and worktrees), rather than
// assuming .git/hooks.
func gitHooksDir() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--git-path", "hooks").Output()
	if err != nil {
		return "", fmt.Errorf("resolving git hooks directory (not a git repository?): %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func preCommitHookScript(failOn string) string {
	return fmt.Sprintf(`#!/bin/sh
%s
# Blocks this commit if a staged change contains a secret at or above
# --fail-on severity. Reinstall with `+"`cerberus git install-hook`"+` to
# change the threshold; delete this file to remove the hook.
exec cerberus git scan . --staged --fail-on %s --format text
`, hookMarker, failOn)
}
