package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/HaK0exe/cerberus/internal/detector"
	"github.com/HaK0exe/cerberus/internal/policy"
	"github.com/HaK0exe/cerberus/internal/rules"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func newScanCmd(flags *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run the detection pipeline against local content",
	}
	cmd.AddCommand(newScanFileCmd(flags))
	return cmd
}

func newScanFileCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "file [path...]",
		Short: "Scan one or more files for exposed secrets",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := buildDetector(flags.rulesDir)
			if err != nil {
				return err
			}

			var all []cerberus.Finding
			for _, path := range args {
				content, err := os.ReadFile(path)
				if err != nil {
					return fmt.Errorf("reading %s: %w", path, err)
				}

				artifact := cerberus.Artifact{
					ID:         path,
					SourceType: cerberus.SourceFile,
					Path:       path,
					Content:    content,
				}

				findings, err := d.Detect(cmd.Context(), artifact)
				if err != nil {
					return fmt.Errorf("scanning %s: %w", path, err)
				}
				all = append(all, findings...)
			}

			return renderFindings(flags.format, all)
		},
	}
}

// buildDetector wires up a Detector against a rules directory using an
// ephemeral, process-local fingerprint key.
//
// TODO(sprint-4): source a stable, persisted fingerprint key from
// config/secret store once the API/storage layer exists — an ephemeral
// key means fingerprints are not stable across CLI invocations.
func buildDetector(rulesDir string) (*detector.Detector, error) {
	compiled, err := rules.LoadDir(os.DirFS("."), rulesDir)
	if err != nil {
		return nil, fmt.Errorf("loading rules from %s: %w", rulesDir, err)
	}
	if len(compiled) == 0 {
		return nil, fmt.Errorf("no rules loaded from %s", rulesDir)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating fingerprint key: %w", err)
	}
	fp, err := policy.NewFingerprinter(key)
	if err != nil {
		return nil, err
	}

	return detector.New(compiled, fp, detector.WithMinEmitBand(detector.BandLowConfidence)), nil
}

func renderFindings(format string, findings []cerberus.Finding) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(findings)
	case "sarif":
		return fmt.Errorf("sarif output is not implemented yet (see Sprint 2)")
	case "text", "":
		if len(findings) == 0 {
			fmt.Println("no findings")
			return nil
		}
		for _, f := range findings {
			fmt.Printf("[%s] %s  %s  confidence=%.2f  %s%s\n",
				f.Severity, f.Type, f.MaskedPrefix, f.Confidence, f.Path, commitSuffix(f.Commit))
		}
		return nil
	default:
		return fmt.Errorf("unknown format %q (want json|text|sarif)", format)
	}
}

func commitSuffix(commit string) string {
	if commit == "" {
		return ""
	}
	return "@" + commit
}
