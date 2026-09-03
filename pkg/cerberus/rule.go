package cerberus

// EntropyConfig configures the optional entropy filter for a Rule.
type EntropyConfig struct {
	Enabled   bool    `yaml:"enabled"`
	Threshold float64 `yaml:"threshold,omitempty"`
}

// Rule is a declarative secret-detection rule loaded from rules/*.yaml.
// It contains no executable code: matching and scoring logic lives in
// internal/detector and internal/rules.
type Rule struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`

	Regex       string `yaml:"regex"`
	SecretGroup int    `yaml:"secret_group"`

	Keywords         []string `yaml:"keywords,omitempty"`
	NegativeKeywords []string `yaml:"negative_keywords,omitempty"`

	Entropy EntropyConfig `yaml:"entropy"`

	Severity   Severity `yaml:"severity"`
	Confidence float64  `yaml:"confidence"`
}
