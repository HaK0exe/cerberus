// Package config loads Cerberus configuration from file, environment,
// and CLI flags (viper, wired in Sprint 1 CLI work). This is a minimal
// scaffold sufficient for `cerberus scan file`.
package config

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
