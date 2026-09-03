// Package rules loads and compiles declarative Rule definitions
// (rules/*.yaml) into a form the detector package can execute.
package rules

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
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
