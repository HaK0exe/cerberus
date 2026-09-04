package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/HaK0exe/cerberus/internal/cliui"
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
	verbose    int
	noColor    bool

	ui *cliui.UI
}

// UI returns the shared terminal-output sink for this invocation,
// built lazily from --quiet/-v/--no-color once flags have been parsed.
func (f *globalFlags) UI() *cliui.UI {
	if f.ui == nil {
		f.ui = cliui.New(os.Stdout, os.Stderr, f.quiet, f.verbose, f.noColor)
	}
	return f.ui
}

func newRootCmd() *cobra.Command {
	flags := &globalFlags{}

	root := &cobra.Command{
		Use:           "cerberus",
		Short:         "Cerberus — secret detection, qualification, and controlled remediation",
		Example:       "  cerberus scan file .env\n  cerberus git scan . --format json\n  cerberus web scan https://example.com -v",
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       version.Version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			flags.UI().Banner(version.Version)
		},
	}

	root.PersistentFlags().StringVar(&flags.configPath, "config", "", "path to config file")
	root.PersistentFlags().StringVar(&flags.format, "format", "text", "output format: json|text|sarif|explain")
	root.PersistentFlags().StringVar(&flags.logLevel, "log-level", "info", "log level: debug|info|warn|error")
	root.PersistentFlags().BoolVar(&flags.quiet, "quiet", false, "suppress all diagnostic output (banner, warnings, progress)")
	root.PersistentFlags().BoolVar(&flags.offline, "offline", true, "never make outbound network calls (default: on)")
	root.PersistentFlags().StringVar(&flags.rulesDir, "rules-dir", "rules", "directory containing rule YAML files")
	root.PersistentFlags().CountVarP(&flags.verbose, "verbose", "v", "increase diagnostic verbosity (-v progress, -vv per-request debug)")
	root.PersistentFlags().BoolVar(&flags.noColor, "no-color", false, "disable colored output")

	root.AddCommand(
		newScanCmd(flags),
		newGitCmd(flags),
		newWebCmd(flags),
		newFindingsCmd(flags),
		newCorrelateCmd(flags),
		newCredentialsCmd(flags),
		newIncidentsCmd(flags),
		newPolicyCmd(flags),
		newBenchmarkCmd(flags),
		newRulesCmd(flags),
		newRemediationCmd(flags),
		newServerCmd(flags),
		newMCPCmd(flags),
	)

	return root
}
