// Package rules loads and compiles declarative Rule definitions
// (rules/*.yaml) into a form the detector package can execute.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// CompiledRule pairs a declarative Rule with its compiled regexp so the
// detector never re-compiles patterns per-artifact.
type CompiledRule struct {
	cerberus.Rule
	Pattern *regexp.Regexp
}

// LoadDir walks dir recursively and loads every *.yaml/*.yml file as a
// list of rules.
func LoadDir(fsys fs.FS, dir string) ([]CompiledRule, error) {
	var out []CompiledRule
	seen := make(map[string]string)

	err := fs.WalkDir(fsys, dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		raw, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("reading rule file %s: %w", path, err)
		}

		var fileRules []cerberus.Rule
		if err := yaml.Unmarshal(raw, &fileRules); err != nil {
			return fmt.Errorf("parsing rule file %s: %w", path, err)
		}

		for _, r := range fileRules {
			compiled, err := compile(r)
			if err != nil {
				return fmt.Errorf("compiling rule %q in %s: %w", r.ID, path, err)
			}
			if prev, dup := seen[r.ID]; dup {
				return fmt.Errorf("duplicate rule id %q (in %s and %s)", r.ID, prev, path)
			}
			seen[r.ID] = path
			out = append(out, compiled)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Deterministic emission order: WalkDir order is filesystem-dependent
	// for generic fs.FS, so sort by ID for stable detection output.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Checksum derives a stable, deterministic version identifier for a
// loaded rule set from its content (ID, regex, secret group, keywords,
// entropy config, severity, confidence) — never from load order. Two
// processes that load the same rules always compute the same checksum,
// so it can stand in for a "ruleset version" in DetectionProvenance
// without a separate, hand-maintained version file to fall out of
// sync with the rules themselves.
func Checksum(compiled []CompiledRule) string {
	lines := make([]string, len(compiled))
	for i, c := range compiled {
		lines[i] = fmt.Sprintf("%s|%s|%d|%s|%s|%v|%.4f|%s|%.4f",
			c.ID, c.Regex, c.SecretGroup,
			strings.Join(c.Keywords, ","), strings.Join(c.NegativeKeywords, ","),
			c.Entropy.Enabled, c.Entropy.Threshold,
			c.Severity, c.Confidence)
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:16]
}

func compile(r cerberus.Rule) (CompiledRule, error) {
	if r.ID == "" {
		return CompiledRule{}, fmt.Errorf("rule missing id")
	}
	if r.Regex == "" {
		return CompiledRule{}, fmt.Errorf("rule %q: empty regex", r.ID)
	}
	if r.Confidence < 0 || r.Confidence > 1 {
		return CompiledRule{}, fmt.Errorf("rule %q: confidence %.4f out of range [0,1]", r.ID, r.Confidence)
	}
	switch r.Severity {
	case cerberus.SeverityLow, cerberus.SeverityMedium, cerberus.SeverityHigh, cerberus.SeverityCritical:
	default:
		return CompiledRule{}, fmt.Errorf("rule %q: unknown severity %q", r.ID, r.Severity)
	}
	pattern, err := regexp.Compile(r.Regex)
	if err != nil {
		return CompiledRule{}, fmt.Errorf("invalid regex: %w", err)
	}
	if r.SecretGroup < 0 || r.SecretGroup > pattern.NumSubexp() {
		return CompiledRule{}, fmt.Errorf("rule %q: secret_group %d out of range [0,%d] for regex with %d capture groups", r.ID, r.SecretGroup, pattern.NumSubexp(), pattern.NumSubexp())
	}
	return CompiledRule{Rule: r, Pattern: pattern}, nil
}
