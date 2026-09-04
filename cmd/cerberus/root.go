package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/HaK0exe/cerberus/internal/cliui"
	"github.com/HaK0exe/cerberus/internal/config"
	"github.com/HaK0exe/cerberus/internal/version"
)

// defaultConfigNames are the config files auto-discovered in the
// current directory when --config isn't given — the same
// no-flags-repeated convenience `.eslintrc`/`.golangci.yml`-style
// tools offer, scoped to this one directory (no upward search) so
// behavior never depends on where cerberus happens to be invoked from
// within a larger tree.
var defaultConfigNames = []string{".cerberus.yaml", ".cerberus.yml"}

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

// loadConfig applies a YAML config file — explicit via --config, or
// auto-discovered from defaultConfigNames in the current directory —
// onto f, but only for flags the invocation didn't itself set: an
// explicit CLI flag always wins over a config file value, which in
// turn always wins over the built-in default. A missing default
// config file is not an error (most invocations have none); a missing
// --config-specified file, or one that fails to parse, is.
func (f *globalFlags) loadConfig(cmd *cobra.Command) error {
	path := f.configPath
	explicit := path != ""
	if !explicit {
		for _, candidate := range defaultConfigNames {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
		if path == "" {
			return nil
		}
	}

	cfg, err := config.LoadFile(path)
	if err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("loading config %s: %w", path, err)
	}

	if !cmd.Flags().Changed("rules-dir") && cfg.RulesDir != "" {
		f.rulesDir = cfg.RulesDir
	}
	if !cmd.Flags().Changed("log-level") && cfg.LogLevel != "" {
		f.logLevel = cfg.LogLevel
	}
	if !cmd.Flags().Changed("offline") {
		f.offline = cfg.Offline
	}
	return nil
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
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := flags.loadConfig(cmd); err != nil {
				return err
			}
			flags.UI().Banner(version.Version)
			return nil
		},
	}

	root.PersistentFlags().StringVar(&flags.configPath, "config", "", "path to config file (default: .cerberus.yaml or .cerberus.yml in the current directory, if present)")
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
