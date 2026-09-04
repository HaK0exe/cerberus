package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/HaK0exe/cerberus/internal/detector"
	"github.com/HaK0exe/cerberus/internal/detector/benchmark"
	"github.com/HaK0exe/cerberus/internal/llm/ollama"
	"github.com/HaK0exe/cerberus/internal/policy"
	"github.com/HaK0exe/cerberus/internal/rules"
)

// newBenchmarkCmd exposes the LLM quality-gate harness (issue #23,
// see docs/architecture/llm-quality-gate.md) as `cerberus benchmark
// corpus`: run the labeled testdata/corpus through the detection
// pipeline and report precision/recall/F1.
//
// Without --llm this is the real, deterministic baseline — no network
// call, no LLM, safe to run anywhere including CI. With --llm it wires
// in the exact same validator stack `scan file --llm` uses
// (buildValidator, in this package), so the "LLM-assisted" numbers
// only ever come from a real Ollama/llama.cpp call, never a stand-in —
// this command deliberately does not offer any fake/simulated
// Validator flag. See docs/architecture/llm-quality-gate.md for why:
// this sandbox has no Ollama/llama.cpp server available, so the
// "with LLM" measurement in that report is left as an explicit TODO
// rather than fabricated.
//
// Both detectors are built directly against detector.New here (rather
// than reusing scan.go's buildDetector) because buildDetector always
// passes WithMinEmitBand(BandLowConfidence) — a debug/rule-testing
// override documented on that option — which would emit llm_review-
// band candidates regardless of the Validator's verdict and defeat
// the point of this benchmark. The quality gate in ROADMAP.md is about
// the pipeline's real default (WithMinEmitBand unset, i.e.
// BandFinding — see docs/architecture/scoring.md), so that's what's
// measured here.
func newBenchmarkCmd(flags *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "benchmark",
		Short: "Benchmark the detection pipeline against a labeled corpus",
	}
	cmd.AddCommand(newBenchmarkCorpusCmd(flags))
	return cmd
}

func newBenchmarkCorpusCmd(flags *globalFlags) *cobra.Command {
	lf := &llmFlags{}
	var corpusDir string
	var verbose bool

	cmd := &cobra.Command{
		Use:   "corpus",
		Short: "Run testdata/corpus through the detector and report precision/recall/F1",
		RunE: func(cmd *cobra.Command, args []string) error {
			if lf.enabled && flags.offline {
				return fmt.Errorf("--llm requires --offline=false (cerberus never makes a network call, including to a local Ollama/llama.cpp server, unless you explicitly opt out of --offline)")
			}

			samples, err := benchmark.LoadCorpus(os.DirFS("."), corpusDir)
			if err != nil {
				return fmt.Errorf("loading corpus: %w", err)
			}

			compiled, fp, err := loadBenchmarkRules(flags.rulesDir)
			if err != nil {
				return err
			}

			baseline := detector.New(compiled, fp)
			baseRes, err := benchmark.Run(cmd.Context(), baseline, samples)
			if err != nil {
				return fmt.Errorf("running baseline benchmark: %w", err)
			}

			fmt.Printf("corpus:   %d samples (%s)\n", len(samples), corpusDir)
			printMetrics(cmd.OutOrStdout(), "baseline (no LLM)", baseRes.Metrics)
			if verbose {
				printSampleOutcomes(cmd.OutOrStdout(), baseRes)
			}

			if lf.enabled {
				validator, err := buildValidator(lf)
				if err != nil {
					return err
				}
				withLLM := detector.New(compiled, fp, detector.WithValidator(validator))
				llmRes, err := benchmark.Run(cmd.Context(), withLLM, samples)
				if err != nil {
					return fmt.Errorf("running LLM-assisted benchmark: %w", err)
				}
				printMetrics(cmd.OutOrStdout(), "LLM-assisted (--llm)", llmRes.Metrics)
				if verbose {
					printSampleOutcomes(cmd.OutOrStdout(), llmRes)
				}
			} else {
				fmt.Println("\n(pass --llm --offline=false to also measure the LLM-assisted pipeline against a real Ollama/llama.cpp server)")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&corpusDir, "corpus-dir", "testdata/corpus", "directory containing true_positive/ and false_positive/ labeled samples")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "print the per-sample tp/fn/fp/tn outcome for every corpus file")
	cmd.Flags().BoolVar(&lf.enabled, "llm", false, "also run the corpus through the LLM-assisted pipeline (requires --offline=false and a reachable Ollama/llama.cpp server)")
	cmd.Flags().StringVar(&lf.model, "llm-model", "llama3.1:8b", "Ollama model to use as the primary LLM validator")
	cmd.Flags().StringVar(&lf.baseURL, "llm-base-url", ollama.DefaultBaseURL, "base URL of the local Ollama server")
	cmd.Flags().StringVar(&lf.llamacppBaseURL, "llm-fallback-base-url", "", "base URL of a local llama.cpp server used as a fallback if Ollama is unavailable (disabled if empty)")
	cmd.Flags().StringVar(&lf.llamacppModel, "llm-fallback-model", "", "model name/path to request from the llama.cpp fallback server (defaults to --llm-model)")

	return cmd
}

// loadBenchmarkRules loads the rule set and a fresh ephemeral
// fingerprint key — same pattern as scan.go's buildDetector, minus the
// BandLowConfidence override (see newBenchmarkCmd's doc comment).
func loadBenchmarkRules(rulesDir string) ([]rules.CompiledRule, *policy.Fingerprinter, error) {
	compiled, err := rules.LoadDir(os.DirFS("."), rulesDir)
	if err != nil {
		return nil, nil, fmt.Errorf("loading rules from %s: %w", rulesDir, err)
	}
	if len(compiled) == 0 {
		return nil, nil, fmt.Errorf("no rules loaded from %s", rulesDir)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, fmt.Errorf("generating fingerprint key: %w", err)
	}
	fp, err := policy.NewFingerprinter(key)
	if err != nil {
		return nil, nil, err
	}

	return compiled, fp, nil
}

func printSampleOutcomes(w interface{ Write([]byte) (int, error) }, res benchmark.Result) {
	for _, sr := range res.Samples {
		errSuffix := ""
		if sr.Err != nil {
			errSuffix = fmt.Sprintf(" (error: %v)", sr.Err)
		}
		fmt.Fprintf(w, "  %-4s %s%s\n", sr.Outcome(), sr.Sample.Path, errSuffix)
	}
}

func printMetrics(w interface{ Write([]byte) (int, error) }, label string, m benchmark.Metrics) {
	fmt.Fprintf(w, "\n%s\n", label)
	fmt.Fprintf(w, "  precision: %.4f\n", m.Precision)
	fmt.Fprintf(w, "  recall:    %.4f\n", m.Recall)
	fmt.Fprintf(w, "  F1:        %.4f\n", m.F1)
	fmt.Fprintf(w, "  confusion: tp=%d fn=%d fp=%d tn=%d (n=%d)\n",
		m.Confusion.TruePositives, m.Confusion.FalseNegatives,
		m.Confusion.FalsePositives, m.Confusion.TrueNegatives, m.Confusion.Total())
}
