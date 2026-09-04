// Package benchmark implements the precision/recall/F1 measurement
// harness for the "LLM quality gate" (see ROADMAP.md's Sprint 3 entry
// and docs/architecture/llm-quality-gate.md): run the labeled corpus
// under testdata/corpus through a detector.Detector with and without a
// cerberus.Validator wired in, and compare the resulting metrics.
//
// This package only reads internal/detector and internal/rules — it
// does not modify either, per the corpus/quality-gate work being kept
// separate from the Sprint 3 detector wiring itself.
package benchmark

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// Label is the ground truth assigned to a corpus sample.
type Label bool

const (
	// TruePositive samples contain exactly one synthetic secret that a
	// correctly-tuned detector should emit as a Finding.
	TruePositive Label = true
	// FalsePositive samples contain no real secret; a correctly-tuned
	// detector should emit zero Findings for them. The name mirrors
	// the corpus directory ("false_positive" = "samples that would be
	// a false positive if flagged"), not the confusion-matrix outcome.
	FalsePositive Label = false
)

// Sample is one labeled corpus artifact.
type Sample struct {
	// Path is the sample's path relative to the corpus root, e.g.
	// "true_positive/aws-access-key-id_basic.env".
	Path string
	// Label is the ground truth for this sample: TruePositive means
	// the file contains a real (synthetic) secret; FalsePositive means
	// it does not.
	Label Label
	// Artifact is the cerberus.Artifact built from the sample's
	// content, ready to hand to a Detector.
	Artifact cerberus.Artifact
}

// trueDir and falseDir are the two label directories under the corpus
// root. See docs/development/corpus.md for the corpus conventions this
// mirrors.
const (
	trueDir  = "true_positive"
	falseDir = "false_positive"
)

// LoadCorpus walks dir (typically "testdata/corpus") and loads every
// file under its true_positive/ and false_positive/ subdirectories as
// a labeled Sample. Files elsewhere under dir, and dotfiles, are
// ignored. It returns an error if dir contains neither subdirectory,
// or if any file cannot be read.
func LoadCorpus(fsys fs.FS, dir string) ([]Sample, error) {
	var samples []Sample

	for _, sub := range []struct {
		name  string
		label Label
	}{
		{trueDir, TruePositive},
		{falseDir, FalsePositive},
	} {
		root := filepath.Join(dir, sub.name)
		entries, err := fs.ReadDir(fsys, root)
		if err != nil {
			return nil, fmt.Errorf("reading corpus directory %s: %w", root, err)
		}

		for _, e := range entries {
			if e.IsDir() || len(e.Name()) == 0 || e.Name()[0] == '.' {
				continue
			}

			p := filepath.Join(root, e.Name())
			content, err := fs.ReadFile(fsys, p)
			if err != nil {
				return nil, fmt.Errorf("reading corpus sample %s: %w", p, err)
			}

			relPath := filepath.Join(sub.name, e.Name())
			samples = append(samples, Sample{
				Path:  relPath,
				Label: sub.label,
				Artifact: cerberus.Artifact{
					ID:         relPath,
					SourceType: cerberus.SourceFile,
					Path:       relPath,
					Content:    content,
				},
			})
		}
	}

	if len(samples) == 0 {
		return nil, fmt.Errorf("no corpus samples found under %s (expected %s/ and %s/ subdirectories)", dir, trueDir, falseDir)
	}

	// Deterministic order regardless of filesystem iteration order —
	// makes benchmark output (and any future golden-file test)
	// reproducible.
	sort.Slice(samples, func(i, j int) bool { return samples[i].Path < samples[j].Path })

	return samples, nil
}
