package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

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

	cmd := &cobra.Command{
		Use:   "file [path...]",
		Short: "Scan one or more files for exposed secrets",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if lf.enabled && flags.offline {
				return fmt.Errorf("--llm requires --offline=false (cerberus never makes a network call, including to a local Ollama/llama.cpp server, unless you explicitly opt out of --offline)")
			}

			d, err := buildDetector(flags.rulesDir, lf)
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

	cmd.Flags().BoolVar(&lf.enabled, "llm", false, "route llm_review-band candidates through a local LLM validator (requires --offline=false)")
	cmd.Flags().StringVar(&lf.model, "llm-model", "llama3.1:8b", "Ollama model to use as the primary LLM validator")
	cmd.Flags().StringVar(&lf.baseURL, "llm-base-url", ollama.DefaultBaseURL, "base URL of the local Ollama server")
	cmd.Flags().StringVar(&lf.llamacppBaseURL, "llm-fallback-base-url", "", "base URL of a local llama.cpp server used as a fallback if Ollama is unavailable (disabled if empty)")
	cmd.Flags().StringVar(&lf.llamacppModel, "llm-fallback-model", "", "model name/path to request from the llama.cpp fallback server (defaults to --llm-model)")

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
func buildDetector(rulesDir string, lf *llmFlags) (*detector.Detector, error) {
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

	opts := []detector.Option{detector.WithMinEmitBand(detector.BandLowConfidence)}

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

func renderFindings(format string, findings []cerberus.Finding) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(findings)
	case "sarif":
		return sarif.Write(os.Stdout, findings, "cerberus", version.Version)
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
