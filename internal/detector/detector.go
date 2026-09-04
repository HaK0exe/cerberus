// Package detector implements the deterministic secret-detection
// pipeline: rule matching, entropy filtering, context-based scoring,
// and Finding assembly. It knows nothing about AWS, HTTP, or MCP.
package detector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/HaK0exe/cerberus/internal/llm"
	"github.com/HaK0exe/cerberus/internal/policy"
	"github.com/HaK0exe/cerberus/internal/rules"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// Detector is the deterministic (regex + entropy + context) detection
// engine. It implements cerberus.Detector.
//
// LLM validation for the [ThresholdLLMReview, ThresholdFinding) band is
// a separate, optional stage: a cerberus.Validator composed (typically
// via internal/llm/pipeline) from an Ollama/llama.cpp adapter wrapped
// in internal/llm/circuitbreaker and internal/llm/cache, and wired in
// via WithValidator. It is entirely optional — a Detector built without
// one behaves exactly as it did before Sprint 3 (BandLLMReview
// candidates are dropped unless WithMinEmitBand lowers the bar) — see
// docs/architecture/overview.md's "Detection pipeline" diagram.
type Detector struct {
	rules       []rules.CompiledRule
	fingerprint *policy.Fingerprinter
	minEmitBand Band // lowest band this detector emits as a Finding on its own
	validator   cerberus.Validator
}

type Option func(*Detector)

// WithMinEmitBand overrides the lowest band emitted without LLM review.
// Defaults to BandFinding; callers wiring an LLM validator in front of
// this detector should keep the default and treat BandLLMReview
// candidates separately.
func WithMinEmitBand(b Band) Option {
	return func(d *Detector) { d.minEmitBand = b }
}

// WithValidator wires an optional cerberus.Validator in front of the
// detector for the BandLLMReview band only: BandFinding and BandIgnore
// (and BandLowConfidence) candidates never reach it — no network call
// is ever made for them. v is expected to already be the fully
// composed stack (timeout + circuit breaker + response cache); see
// internal/llm/pipeline.New. A nil v (the default) leaves the detector
// in its Sprint-1, LLM-free mode.
//
// The Detector never treats a Validator error as fatal: any failure
// (timeout, circuit open, transport error, ...) makes the candidate
// fall back to its pre-LLM deterministic score, exactly as if
// WithValidator had not been called for that candidate — see
// docs/architecture/llm-non-sovereign.md and
// internal/llm/circuitbreaker's ErrFallback/IsFallback.
func WithValidator(v cerberus.Validator) Option {
	return func(d *Detector) { d.validator = v }
}

func New(compiledRules []rules.CompiledRule, fp *policy.Fingerprinter, opts ...Option) *Detector {
	d := &Detector{
		rules:       compiledRules,
		fingerprint: fp,
		minEmitBand: BandFinding,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

func (d *Detector) Detect(ctx context.Context, artifact cerberus.Artifact) ([]cerberus.Finding, error) {
	var findings []cerberus.Finding

	for _, rule := range d.rules {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		locs := rule.Pattern.FindAllSubmatchIndex(artifact.Content, -1)
		for _, loc := range locs {
			start, end := loc[0], loc[1]
			if rule.SecretGroup > 0 && len(loc) > rule.SecretGroup*2+1 {
				start, end = loc[rule.SecretGroup*2], loc[rule.SecretGroup*2+1]
			}
			if start < 0 || end < 0 || end > len(artifact.Content) {
				continue
			}

			value := artifact.Content[start:end]
			s := score(rule, artifact.Content, start, end)
			band := Classify(s)

			shouldEmit := bandRank(band) >= bandRank(d.minEmitBand)
			var llmMeta map[string]string

			// Only the ambiguous llm_review band is ever routed to the
			// optional Validator — BandFinding and BandIgnore/
			// BandLowConfidence candidates bypass it completely, so a
			// Detector with no Validator configured (d.validator == nil)
			// never even reaches this branch and never makes a network
			// call. See docs/architecture/overview.md's pipeline diagram.
			if band == BandLLMReview && d.validator != nil {
				select {
				case <-ctx.Done():
					return findings, ctx.Err()
				default:
				}

				ctxStart, ctxEnd := contextWindowBounds(len(artifact.Content), start, end)
				rawContext := string(artifact.Content[ctxStart:ctxEnd])

				input := cerberus.ValidationInput{
					RuleID: rule.ID,
					// Always sanitized before it ever leaves the detector —
					// never send raw context to a Validator. See
					// docs/architecture/llm-non-sovereign.md.
					RedactedContext: llm.Sanitize(rawContext, value),
					Entropy:         ShannonEntropy(value),
					Path:            artifact.Path,
				}

				result, verr := d.validator.Validate(ctx, input)
				if verr != nil {
					if ctxErr := ctx.Err(); ctxErr != nil {
						// The caller gave up, not the Validator — propagate
						// its own cancellation rather than silently
						// swallowing it.
						return findings, ctxErr
					}
					// Any other Validator failure (timeout, circuit open,
					// transport error, malformed response degraded to a
					// fallback result upstream, ...) is non-blocking: the
					// candidate keeps its deterministic pre-LLM score and
					// band, exactly as if no Validator were configured.
					// See internal/llm/circuitbreaker.IsFallback.
				} else {
					s = adjustScore(s, result)
					llmMeta = map[string]string{
						"llm_classification": string(result.Classification),
						"llm_reason":         result.Reason,
					}

					// The Validator is never sovereign (it only ever
					// shifted s within the llm_review band above): it may
					// only decide whether *this* already-flagged ambiguous
					// candidate is surfaced to the caller, not fabricate a
					// Finding for a candidate that was never a candidate,
					// nor erase a Finding the deterministic stage already
					// committed to (BandFinding bypasses this branch
					// entirely).
					switch result.Classification {
					case cerberus.ClassificationLikelySecret:
						shouldEmit = true
					case cerberus.ClassificationLikelyFalsePos:
						shouldEmit = false
					default: // uncertain: defer to the configured minEmitBand
					}
				}
			}

			if !shouldEmit {
				continue
			}

			f := cerberus.Finding{
				ID:           newID("fnd"),
				RuleID:       rule.ID,
				Type:         rule.ID,
				Severity:     rule.Severity,
				Confidence:   s,
				SourceType:   artifact.SourceType,
				SourceURI:    artifact.URI,
				Path:         artifact.Path,
				Commit:       artifact.Commit,
				State:        cerberus.StateOpen,
				CreatedAt:    time.Now().UTC(),
				UpdatedAt:    time.Now().UTC(),
				MaskedPrefix: policy.MaskedPrefix(value, 4),
				Length:       len(value),
			}
			if d.fingerprint != nil {
				f.Fingerprint = d.fingerprint.Fingerprint(value)
			}
			if llmMeta != nil {
				f.Metadata = llmMeta
			}

			// NB: value is a subslice of artifact.Content, which is
			// shared across rules and callers — it is not ours to
			// zero here. policy.Zero applies to buffers a caller owns
			// exclusively (e.g. a copied candidate handed to an LLM
			// validator).
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// llmScoreEpsilon keeps an LLM-adjusted score strictly below
// ThresholdFinding: a Validator may shift a score within the
// llm_review band, but must never be able to push a candidate into the
// finding band on its own (see docs/architecture/llm-non-sovereign.md).
const llmScoreEpsilon = 0.001

// adjustScore folds a Validator's classification/confidence into the
// pre-LLM deterministic score s, clamped so the result always stays
// inside [ThresholdLLMReview, ThresholdFinding) regardless of what the
// Validator returned — a Validator is never sovereign: it can shift a
// score within the llm_review band, never move a candidate out of it.
func adjustScore(s float64, result cerberus.ValidationResult) float64 {
	lo, hi := ThresholdLLMReview, ThresholdFinding-llmScoreEpsilon

	adjusted := s
	switch result.Classification {
	case cerberus.ClassificationLikelySecret:
		// Higher Validator confidence pushes the score toward the top
		// of the band.
		adjusted = ThresholdLLMReview + result.Confidence*(ThresholdFinding-ThresholdLLMReview)
	case cerberus.ClassificationLikelyFalsePos:
		// Higher Validator confidence (in it being a false positive)
		// pushes the score toward the bottom of the band.
		adjusted = ThresholdFinding - result.Confidence*(ThresholdFinding-ThresholdLLMReview)
	default:
		// Uncertain, or any classification value the schema layer let
		// through that this detector doesn't specifically recognize:
		// leave the deterministic score untouched.
	}

	if adjusted < lo {
		adjusted = lo
	}
	if adjusted > hi {
		adjusted = hi
	}
	return adjusted
}

func bandRank(b Band) int {
	switch b {
	case BandIgnore:
		return 0
	case BandLowConfidence:
		return 1
	case BandLLMReview:
		return 2
	case BandFinding:
		return 3
	default:
		return 0
	}
}

func newID(prefix string) string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return prefix + "_" + hex.EncodeToString(buf)
}
