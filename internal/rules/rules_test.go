package rules_test

import (
	"regexp"
	"testing"

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
