package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cerberus.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFile_DefaultsPreserved(t *testing.T) {
	path := writeConfig(t, "log_level: debug\n")
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("got log_level %q", cfg.LogLevel)
	}
	if cfg.RulesDir != "builtin" {
		t.Errorf("rules_dir should default to 'builtin', got %q", cfg.RulesDir)
	}
	if !cfg.Offline {
		t.Error("offline should default to true")
	}
}

func TestLoadFile_ExplicitOfflineFalse(t *testing.T) {
	path := writeConfig(t, "offline: false\n")
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.Offline {
		t.Error("explicit offline:false must be honored")
	}
}

func TestLoadFile_RejectsUnknownField(t *testing.T) {
	path := writeConfig(t, "rule_dir: rules\n")
	if _, err := LoadFile(path); err == nil {
		t.Error("expected typo'd key to be rejected by strict decoding")
	}
}

func TestLoadFile_RejectsBadLogLevel(t *testing.T) {
	path := writeConfig(t, "log_level: verbose\n")
	if _, err := LoadFile(path); err == nil {
		t.Error("expected invalid log_level to be rejected")
	}
}

func TestLoadFile_MissingFile(t *testing.T) {
	if _, err := LoadFile(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected missing file to error")
	}
}
