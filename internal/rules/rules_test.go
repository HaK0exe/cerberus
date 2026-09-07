package rules_test

import (
	"regexp"
	"testing"
	"testing/fstest"

	"github.com/HaK0exe/cerberus/internal/rules"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func compiled(r cerberus.Rule) rules.CompiledRule {
	return rules.CompiledRule{Rule: r, Pattern: regexp.MustCompile("x")}
}

func TestChecksum_StableAcrossOrder(t *testing.T) {
	a := compiled(cerberus.Rule{ID: "rule-a", Regex: "x", Confidence: 0.9})
	b := compiled(cerberus.Rule{ID: "rule-b", Regex: "x", Confidence: 0.5})

	c1 := rules.Checksum([]rules.CompiledRule{a, b})
	c2 := rules.Checksum([]rules.CompiledRule{b, a})

	if c1 != c2 {
		t.Errorf("checksum should not depend on load order: %q vs %q", c1, c2)
	}
}

func TestChecksum_ChangesWithContent(t *testing.T) {
	a := compiled(cerberus.Rule{ID: "rule-a", Regex: "x", Confidence: 0.9})
	aChanged := compiled(cerberus.Rule{ID: "rule-a", Regex: "x", Confidence: 0.8})

	if rules.Checksum([]rules.CompiledRule{a}) == rules.Checksum([]rules.CompiledRule{aChanged}) {
		t.Error("checksum should change when a rule's confidence changes")
	}
}

func loadYAML(t *testing.T, name, content string) error {
	t.Helper()
	fsys := fstest.MapFS{name: {Data: []byte(content)}}
	_, err := rules.LoadDir(fsys, ".")
	return err
}

func TestLoadDir_RejectsBadSecretGroup(t *testing.T) {
	// Regex has 1 capture group but secret_group points to 2.
	if err := loadYAML(t, "bad.yaml", "- id: bad\n  regex: '(a)'\n  secret_group: 2\n  severity: high\n  confidence: 0.9\n"); err == nil {
		t.Error("expected secret_group out of range to be rejected")
	}
}

func TestLoadDir_RejectsBadConfidence(t *testing.T) {
	if err := loadYAML(t, "bad.yaml", "- id: bad\n  regex: 'x'\n  secret_group: 0\n  severity: high\n  confidence: 1.5\n"); err == nil {
		t.Error("expected confidence >1 to be rejected")
	}
}

func TestLoadDir_RejectsDuplicateID(t *testing.T) {
	fsys := fstest.MapFS{
		"a.yaml": {Data: []byte("- id: dup\n  regex: 'x'\n  secret_group: 0\n  severity: high\n  confidence: 0.9\n")},
		"b.yaml": {Data: []byte("- id: dup\n  regex: 'y'\n  secret_group: 0\n  severity: high\n  confidence: 0.9\n")},
	}
	if _, err := rules.LoadDir(fsys, "."); err == nil {
		t.Error("expected duplicate rule id to be rejected")
	}
}

func TestLoadDir_RejectsUnknownSeverity(t *testing.T) {
	if err := loadYAML(t, "bad.yaml", "- id: bad\n  regex: 'x'\n  secret_group: 0\n  severity: nope\n  confidence: 0.9\n"); err == nil {
		t.Error("expected unknown severity to be rejected")
	}
}
