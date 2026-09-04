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
			out = append(out, compiled)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
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
	pattern, err := regexp.Compile(r.Regex)
	if err != nil {
		return CompiledRule{}, fmt.Errorf("invalid regex: %w", err)
	}
	return CompiledRule{Rule: r, Pattern: pattern}, nil
}
