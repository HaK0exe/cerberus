// Package detector implements the deterministic secret-detection
// pipeline: rule matching, entropy filtering, context-based scoring,
// and Finding assembly. It knows nothing about AWS, HTTP, or MCP.
package detector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/HaK0exe/cerberus/internal/policy"
	"github.com/HaK0exe/cerberus/internal/rules"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// Detector is the deterministic (regex + entropy + context) detection
// engine. It implements cerberus.Detector.
//
// LLM validation for the [ThresholdLLMReview, ThresholdFinding) band is
// a separate, optional stage (internal/llm) composed on top of this one
// — see docs/architecture/pipeline.md.
type Detector struct {
	rules       []rules.CompiledRule
	fingerprint *policy.Fingerprinter
	minEmitBand Band // lowest band this detector emits as a Finding on its own
}

type Option func(*Detector)

// WithMinEmitBand overrides the lowest band emitted without LLM review.
// Defaults to BandFinding; callers wiring an LLM validator in front of
// this detector should keep the default and treat BandLLMReview
// candidates separately.
func WithMinEmitBand(b Band) Option {
	return func(d *Detector) { d.minEmitBand = b }
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

			if bandRank(band) < bandRank(d.minEmitBand) {
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
