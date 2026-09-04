// Package bench implements a reproducible detection benchmark:
// running internal/detector against testdata/corpus and computing
// precision/recall/F1 so a rule or scoring change can show a BEFORE/
// AFTER comparison instead of relying on intuition. See
// docs/architecture/scoring.md, which references this corpus for
// calibration.
//
// Deliberately out of scope for this package (see Report's doc
// comment): allocation counters and LLM call/latency metrics — both
// need a live/fake Validator and testing.B-style instrumentation this
// slice doesn't wire up. Adding fabricated numbers for those would be
// worse than omitting them.
package bench

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// ExpectedResult is the machine-readable manifest for one corpus
// sample, loaded from a "<sample>.expected.json" sidecar file next to
// it.
type ExpectedResult struct {
	// ExpectFindings is true for testdata/corpus/true-positives
	// samples (Detect must produce at least one matching Finding) and
	// false for testdata/corpus/false-positives samples (Detect must
	// produce none).
	ExpectFindings bool `json:"expect_findings"`

	// RuleID, when set, narrows a true-positive expectation to a
	// specific rule — a Finding from an unrelated rule doesn't satisfy
	// it. Ignored when ExpectFindings is false.
	RuleID string `json:"rule_id,omitempty"`

	// MinConfidence, when set, additionally requires the matching
	// Finding's Confidence to be at least this value.
	MinConfidence float64 `json:"min_confidence,omitempty"`
}

// Sample is one loaded corpus fixture: content plus what Detect is
// expected to do with it.
type Sample struct {
	Path     string
	Content  []byte
	Expected ExpectedResult
}

// LoadCorpus walks dir (mirroring internal/rules.LoadDir's fs.FS-based
// pattern) and loads every fixture file paired with a
// "<name>.expected.json" sidecar into a Sample. Files without a
// sidecar are skipped with an error — every fixture must declare its
// expectation explicitly, never be silently ignored or silently
// assumed benign.
func LoadCorpus(fsys fs.FS, dir string) ([]Sample, error) {
	var out []Sample

	err := fs.WalkDir(fsys, dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.HasSuffix(path, ".expected.json") {
			return nil
		}

		content, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("reading sample %s: %w", path, err)
		}

		sidecar := path + ".expected.json"
		raw, err := fs.ReadFile(fsys, sidecar)
		if err != nil {
			return fmt.Errorf("sample %s has no matching %s: %w", path, filepath.Base(sidecar), err)
		}

		var expected ExpectedResult
		if err := json.Unmarshal(raw, &expected); err != nil {
			return fmt.Errorf("parsing %s: %w", sidecar, err)
		}

		out = append(out, Sample{Path: path, Content: content, Expected: expected})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
