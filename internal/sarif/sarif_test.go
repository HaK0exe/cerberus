package sarif_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/HaK0exe/cerberus/internal/sarif"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func TestWrite_NoRawSecretAndValidShape(t *testing.T) {
	findings := []cerberus.Finding{
		{
			RuleID:       "aws-access-key-id",
			Type:         "aws-access-key-id",
			Severity:     cerberus.SeverityHigh,
			Fingerprint:  "cerberus:hmac-sha256:deadbeef",
			MaskedPrefix: "AKIA****************",
			Path:         "config/prod.env",
			Commit:       "abc123",
		},
	}

	var buf bytes.Buffer
	if err := sarif.Write(&buf, findings, "cerberus", "0.1.0-test"); err != nil {
		t.Fatalf("Write: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "AKIAABCDEFGHIJKLMNOP") {
		t.Fatal("SARIF output must never contain a raw secret value")
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("expected sarif version 2.1.0, got %v", doc["version"])
	}

	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected exactly one run, got %v", doc["runs"])
	}
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("expected exactly one result, got %d", len(results))
	}

	result := results[0].(map[string]any)
	if result["ruleId"] != "aws-access-key-id" {
		t.Errorf("unexpected ruleId: %v", result["ruleId"])
	}
	if result["level"] != "error" {
		t.Errorf("expected severity=high to map to level=error, got %v", result["level"])
	}

	locations := result["locations"].([]any)
	loc := locations[0].(map[string]any)
	physical := loc["physicalLocation"].(map[string]any)
	artifactLocation := physical["artifactLocation"].(map[string]any)
	if artifactLocation["uri"] != "config/prod.env" {
		t.Errorf("unexpected artifact uri: %v", artifactLocation["uri"])
	}

	props := result["properties"].(map[string]any)
	if props["commit"] != "abc123" {
		t.Errorf("expected commit property to be set, got %v", props["commit"])
	}
}

func TestWrite_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := sarif.Write(&buf, nil, "cerberus", "dev"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}
