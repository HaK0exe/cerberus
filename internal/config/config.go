// Package config loads Cerberus configuration from a YAML file, so
// repeated CLI flags (--rules-dir, --log-level, --offline) can be set
// once per project instead of on every invocation. CLI flags always
// take precedence over a config file value — see LoadFile and
// cmd/cerberus/root.go's globalFlags.loadConfig.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure. Fields are added
// incrementally as each subsystem needs them — do not pre-populate
// speculative fields.
type Config struct {
	RulesDir       string `yaml:"rules_dir"`
	LogLevel       string `yaml:"log_level"`
	Offline        bool   `yaml:"offline"`
	FingerprintKey string `yaml:"-"` // sourced from env/secret store only, never from a config file
}

func Default() Config {
	return Config{
		RulesDir: "rules",
		LogLevel: "info",
		Offline:  true,
	}
}

// LoadFile reads a YAML config file at path, starting from Default()
// so fields the file omits keep their defaults rather than zeroing
// out (e.g. an explicit `offline: false` overrides the default, but a
// file that never mentions `offline` at all doesn't accidentally flip
// it to false either — yaml.Unmarshal only touches keys present in
// the document).
func LoadFile(path string) (Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied config file
	if err != nil {
		return Config{}, err
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing config: %w", err)
	}
	return cfg, nil
}
