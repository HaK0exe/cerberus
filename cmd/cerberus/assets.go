package main

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/HaK0exe/cerberus/internal/detector/benchmark"
	"github.com/HaK0exe/cerberus/internal/llm/prompt"
	"github.com/HaK0exe/cerberus/internal/rules"
	builtinprompts "github.com/HaK0exe/cerberus/prompts"
	builtinrules "github.com/HaK0exe/cerberus/rules"
)

const defaultRulesDir = "builtin"

func loadRules(path string) ([]rules.CompiledRule, error) {
	if filepath.Clean(path) == defaultRulesDir {
		return rules.LoadDir(builtinrules.FS, ".")
	}
	fsys, err := dirFS(path)
	if err != nil {
		return nil, err
	}
	return rules.LoadDir(fsys, ".")
}

func loadPrompts() (*prompt.Store, error) {
	return prompt.LoadDir(builtinprompts.FS, ".")
}

func loadCorpus(path string) ([]benchmark.Sample, error) {
	fsys, err := dirFS(path)
	if err != nil {
		return nil, err
	}
	return benchmark.LoadCorpus(fsys, ".")
}

func dirFS(path string) (fs.FS, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return os.DirFS(abs), nil
}
