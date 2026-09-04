package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/HaK0exe/cerberus/internal/cliui"
	"github.com/HaK0exe/cerberus/internal/detector"
	"github.com/HaK0exe/cerberus/internal/llm/cache"
	"github.com/HaK0exe/cerberus/internal/llm/circuitbreaker"
	"github.com/HaK0exe/cerberus/internal/llm/llamacpp"
	"github.com/HaK0exe/cerberus/internal/llm/ollama"
	"github.com/HaK0exe/cerberus/internal/llm/pipeline"
	"github.com/HaK0exe/cerberus/internal/llm/prompt"
	"github.com/HaK0exe/cerberus/internal/policy"
	"github.com/HaK0exe/cerberus/internal/rules"
	"github.com/HaK0exe/cerberus/internal/sarif"
	"github.com/HaK0exe/cerberus/internal/version"
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

// llmFlags holds the opt-in flags that enable the Sprint 3 LLM review
// stage for `scan file`. They are only meaningful together with
// --offline=false: cerberus never makes an outbound (even
// localhost-bound) call on its own say-so.
type llmFlags struct {
	enabled         bool
	model           string
	baseURL         string
	llamacppBaseURL string
	llamacppModel   string
}

func newScanFileCmd(flags *globalFlags) *cobra.Command {
	lf := &llmFlags{}
	var unmask bool
	var failOn string

	cmd := &cobra.Command{
		Use:   "file [path...]",
		Short: "Scan one or more files for exposed secrets",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			failOnSeverity, err := parseFailOn(failOn)
			if err != nil {
				return err
			}
			if lf.enabled && flags.offline {
				return fmt.Errorf("--llm requires --offline=false (cerberus never makes a network call, including to a local Ollama/llama.cpp server, unless you explicitly opt out of --offline)")
			}
			warnUnmask(flags.UI(), unmask)

			d, err := buildDetector(flags.rulesDir, lf, unmask)
			if err != nil {
				return err
			}

			var all []cerberus.Finding
			for _, path := range args {
				content, err := os.ReadFile(path) // #nosec G304 -- path is a scan target supplied on the CLI command line
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

			if err := renderFindings(flags.UI(), flags.format, all); err != nil {
				return err
			}
			return checkFailOn(all, failOnSeverity)
		},
	}

	cmd.Flags().BoolVar(&lf.enabled, "llm", false, "route llm_review-band candidates through a local LLM validator (requires --offline=false)")
	cmd.Flags().StringVar(&lf.model, "llm-model", "llama3.1:8b", "Ollama model to use as the primary LLM validator")
	cmd.Flags().StringVar(&lf.baseURL, "llm-base-url", ollama.DefaultBaseURL, "base URL of the local Ollama server")
	cmd.Flags().StringVar(&lf.llamacppBaseURL, "llm-fallback-base-url", "", "base URL of a local llama.cpp server used as a fallback if Ollama is unavailable (disabled if empty)")
	cmd.Flags().StringVar(&lf.llamacppModel, "llm-fallback-model", "", "model name/path to request from the llama.cpp fallback server (defaults to --llm-model)")
	cmd.Flags().BoolVar(&unmask, "unmask", false, "print full secret values instead of a masked hint (local triage only — never use in CI/logs)")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero if any finding is at or above this severity: critical|high|medium|low (default: never fail, exit 0) — for CI/git-hook gating")

	return cmd
}

// buildDetector wires up a Detector against a rules directory using an
// ephemeral, process-local fingerprint key, and — when lf.enabled — the
// optional Sprint 3 LLM review stage for the llm_review band (see
// internal/llm/pipeline and docs/architecture/overview.md's "Detection
// pipeline"). A nil/disabled lf preserves the pre-Sprint-3 behavior
// exactly: no Validator is wired in, and the detector never makes an
// outbound call.
//
// TODO(sprint-4): source a stable, persisted fingerprint key from
// config/secret store once the API/storage layer exists — an ephemeral
// key means fingerprints are not stable across CLI invocations.
func buildDetector(rulesDir string, lf *llmFlags, unmask bool) (*detector.Detector, error) {
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

	opts := []detector.Option{
		detector.WithMinEmitBand(detector.BandLowConfidence),
		detector.WithRevealSecrets(unmask),
	}

	if lf != nil && lf.enabled {
		validator, err := buildValidator(lf)
		if err != nil {
			return nil, err
		}
		opts = append(opts, detector.WithValidator(validator))
	}

	return detector.New(compiled, fp, opts...), nil
}

// buildValidator composes the LLM validator stack described in
// internal/llm/pipeline's doc comment: Ollama as the primary backend,
// optionally a llama.cpp server as a fallback, each wrapped in its own
// timeout + circuit breaker, the whole chain wrapped in an in-memory
// response cache. It is only ever called when the caller has opted in
// via --llm (and --offline=false).
func buildValidator(lf *llmFlags) (cerberus.Validator, error) {
	prompts, err := prompt.LoadDir(os.DirFS("."), "prompts")
	if err != nil {
		return nil, fmt.Errorf("loading LLM prompt templates: %w", err)
	}

	primary, err := ollama.New(ollama.Config{
		BaseURL: lf.baseURL,
		Model:   lf.model,
		Prompts: prompts,
	})
	if err != nil {
		return nil, fmt.Errorf("configuring ollama validator: %w", err)
	}

	var fallback cerberus.Validator
	if lf.llamacppBaseURL != "" {
		llamacppModel := lf.llamacppModel
		if llamacppModel == "" {
			llamacppModel = lf.model
		}
		fallback, err = llamacpp.New(llamacpp.Config{
			BaseURL: lf.llamacppBaseURL,
			Model:   llamacppModel,
		}, prompts)
		if err != nil {
			return nil, fmt.Errorf("configuring llama.cpp fallback validator: %w", err)
		}
	}

	cacheKey := make([]byte, 32)
	if _, err := rand.Read(cacheKey); err != nil {
		return nil, fmt.Errorf("generating LLM cache key: %w", err)
	}
	keyDeriver, err := cache.NewKeyDeriver(cacheKey)
	if err != nil {
		return nil, err
	}

	return pipeline.New(pipeline.Config{
		Primary:  primary,
		Fallback: fallback,
		Breaker: circuitbreaker.Config{
			CallTimeout: 30 * time.Second,
		},
		Cache:           cache.NewMemCache(),
		CacheKey:        keyDeriver,
		CacheTTLSeconds: 300,
		ModelID:         lf.model,
		PromptVersion:   "candidate_validation@1",
		RulesVersion:    "cli-local",
	}), nil
}

// severityRank orders Severity for --fail-on threshold comparisons —
// higher is worse.
var severityRank = map[cerberus.Severity]int{
	cerberus.SeverityLow:      1,
	cerberus.SeverityMedium:   2,
	cerberus.SeverityHigh:     3,
	cerberus.SeverityCritical: 4,
}

// parseFailOn validates a --fail-on flag value. An empty string means
// "never fail" (checkFailOn always returns nil), preserving the
// pre-existing always-exit-0 behavior for callers that don't opt in.
func parseFailOn(s string) (cerberus.Severity, error) {
	if s == "" {
		return "", nil
	}
	sev := cerberus.Severity(strings.ToLower(s))
	if _, ok := severityRank[sev]; !ok {
		return "", fmt.Errorf("invalid --fail-on %q (want critical|high|medium|low)", s)
	}
	return sev, nil
}

// checkFailOn returns a non-nil error when at least one finding is at
// or above threshold, so RunE's returned error drives main.go's
// os.Exit(1) — the exit-code contract CI jobs and git hooks gate on.
// A zero-value threshold ("") always passes.
func checkFailOn(findings []cerberus.Finding, threshold cerberus.Severity) error {
	if threshold == "" {
		return nil
	}
	min := severityRank[threshold]
	var n int
	for _, f := range findings {
		if severityRank[f.Severity] >= min {
			n++
		}
	}
	if n > 0 {
		return fmt.Errorf("%d finding(s) at or above --fail-on=%s severity", n, threshold)
	}
	return nil
}

func renderFindings(ui *cliui.UI, format string, findings []cerberus.Finding) error {
	ui.DoneProgress()
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(findings)
	case "sarif":
		return sarif.Write(os.Stdout, findings, "cerberus", version.Version)
	case "text", "":
		if len(findings) == 0 {
			fmt.Println(ui.Ok("✓ no findings"))
			return nil
		}
		counts := map[cerberus.Severity]int{}
		for _, f := range findings {
			fmt.Printf("[%s] %s  %s  confidence=%.2f  %s%s\n",
				ui.Severity(string(f.Severity)), f.Type, f.MaskedPrefix, f.Confidence, f.Path, commitSuffix(f.Commit))
			counts[f.Severity]++
		}
		fmt.Println()
		fmt.Println(summaryLine(len(findings), counts))
		return nil
	case "explain":
		if len(findings) == 0 {
			fmt.Println(ui.Ok("✓ no findings"))
			return nil
		}
		for i, f := range findings {
			if i > 0 {
				fmt.Println()
			}
			explainFinding(f)
		}
		return nil
	default:
		return fmt.Errorf("unknown format %q (want json|text|sarif|explain)", format)
	}
}

// explainFinding prints the per-signal breakdown behind a Finding's
// Confidence — the offline equivalent of `cerberus findings explain
// <id>` (Sprint 4, once findings are server-persisted). Never prints a
// raw secret value: only what Finding/DetectionProvenance already
// carry (masked prefix, signals, rule/ruleset identity).
func explainFinding(f cerberus.Finding) {
	fmt.Printf("%s  %s  %s%s\n", f.Type, f.MaskedPrefix, f.Path, commitSuffix(f.Commit))
	fmt.Println()
	for _, s := range f.Provenance.Signals {
		fmt.Printf("  %-20s %+.2f   %s\n", s.Name, s.Score, s.Reason)
	}
	fmt.Println()
	fmt.Printf("  final confidence: %.2f (%s)\n", f.Confidence, detector.Classify(f.Confidence))
	fmt.Println()
	fmt.Printf("  rule:      %s\n", f.Provenance.RuleID)
	fmt.Printf("  ruleset:   %s\n", f.Provenance.RulesetVersion)
	fmt.Printf("  detector:  %s\n", f.Provenance.DetectorVersion)
	if f.Provenance.ModelName != "" {
		fmt.Printf("  llm:       %s (prompt %s)\n", f.Provenance.ModelName, f.Provenance.PromptVersion)
	} else {
		fmt.Printf("  llm:       none (deterministic only)\n")
	}
}

// summaryLine renders the sqlmap/katana-style closing line: total
// findings broken down by severity, highest severity first.
func summaryLine(total int, counts map[cerberus.Severity]int) string {
	order := []cerberus.Severity{cerberus.SeverityCritical, cerberus.SeverityHigh, cerberus.SeverityMedium, cerberus.SeverityLow}
	var parts []string
	for _, sev := range order {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	noun := "findings"
	if total == 1 {
		noun = "finding"
	}
	return fmt.Sprintf("%d %s (%s)", total, noun, strings.Join(parts, ", "))
}

// warnUnmask surfaces a one-line reminder on stderr whenever --unmask
// is set, since it's the one flag in this CLI that puts raw secret
// material on stdout (and therefore in scrollback, redirected files,
// or CI logs if the caller isn't careful).
func warnUnmask(ui *cliui.UI, unmask bool) {
	if unmask {
		ui.Warnf("--unmask is on: full secret values will be printed — do not use in CI or pipe to logs")
	}
}

func commitSuffix(commit string) string {
	if commit == "" {
		return ""
	}
	return "@" + commit
}
