package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltInAssetsLoadOutsideRepository(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	compiled, err := loadRules(defaultRulesDir)
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	if len(compiled) == 0 {
		t.Fatal("loadRules returned no built-in rules")
	}
	store, err := loadPrompts()
	if err != nil {
		t.Fatalf("loadPrompts: %v", err)
	}
	if _, err := store.Get("candidate_validation"); err != nil {
		t.Fatalf("candidate_validation prompt: %v", err)
	}
}

func TestLoadRulesAcceptsAbsoluteDirectory(t *testing.T) {
	dir := t.TempDir()
	rule := `
- id: release-smoke-test
  name: Release smoke test
  regex: '(secret_[a-z]+)'
  secret_group: 1
  severity: high
  confidence: 0.95
`
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	compiled, err := loadRules(dir)
	if err != nil {
		t.Fatalf("loadRules(%q): %v", dir, err)
	}
	if len(compiled) != 1 || compiled[0].ID != "release-smoke-test" {
		t.Fatalf("unexpected compiled rules: %#v", compiled)
	}
}

func TestWebProxyFailsClosed(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"--quiet", "--offline=false", "web", "scan", "https://example.com",
		"--proxy", "http://proxy.example",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "mandatory dial-time SSRF validation") {
		t.Fatalf("expected proxy SSRF error, got %v", err)
	}
}
