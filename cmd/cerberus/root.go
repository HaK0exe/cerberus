package main

import (
	"github.com/spf13/cobra"

	"github.com/HaK0exe/cerberus/internal/version"
)

// globalFlags holds the CLI-wide options shared by every subcommand.
type globalFlags struct {
	configPath string
	format     string
	logLevel   string
	quiet      bool
	offline    bool
	rulesDir   string
}

func newRootCmd() *cobra.Command {
	flags := &globalFlags{}

	root := &cobra.Command{
		Use:           "cerberus",
		Short:         "Cerberus — secret detection, qualification, and controlled remediation",
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       version.Version,
	}

	root.PersistentFlags().StringVar(&flags.configPath, "config", "", "path to config file")
	root.PersistentFlags().StringVar(&flags.format, "format", "text", "output format: json|text|sarif")
	root.PersistentFlags().StringVar(&flags.logLevel, "log-level", "info", "log level: debug|info|warn|error")
	root.PersistentFlags().BoolVar(&flags.quiet, "quiet", false, "suppress non-essential output")
	root.PersistentFlags().BoolVar(&flags.offline, "offline", true, "never make outbound network calls (default: on)")
	root.PersistentFlags().StringVar(&flags.rulesDir, "rules-dir", "rules", "directory containing rule YAML files")

	root.AddCommand(
		newScanCmd(flags),
		newGitCmd(flags),
		newWebCmd(flags),
		newFindingsCmd(flags),
		newRulesCmd(flags),
		newRemediationCmd(flags),
		newServerCmd(flags),
		newMCPCmd(flags),
	)

	return root
}
