package aws_test

import (
	"context"
	"testing"

	"github.com/HaK0exe/cerberus/internal/intelligence/aws"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func TestSupports_OnlyAWSProvider(t *testing.T) {
	e := aws.New()

	if !e.Supports(cerberus.Credential{Provider: "aws"}) {
		t.Error("Supports should be true for Provider \"aws\"")
	}
	if e.Supports(cerberus.Credential{Provider: "github"}) {
		t.Error("Supports should be false for a non-aws provider")
	}
	if e.Supports(cerberus.Credential{Provider: ""}) {
		t.Error("Supports should be false for an empty provider")
	}
}

func TestEnrich_ClassifiesKnownRuleIDs(t *testing.T) {
	e := aws.New()

	cases := []struct {
		kind     string
		wantType string
	}{
		{"aws-access-key-id", "access_key_id"},
		{"aws-secret-access-key", "secret_access_key"},
	}

	for _, tc := range cases {
		cred := cerberus.Credential{ID: "cred_1", Provider: "aws", Kind: tc.kind}
		got, err := e.Enrich(context.Background(), cred)
		if err != nil {
			t.Fatalf("Enrich(%q): %v", tc.kind, err)
		}
		if got.CredentialType != tc.wantType {
			t.Errorf("Enrich(%q).CredentialType = %q, want %q", tc.kind, got.CredentialType, tc.wantType)
		}
		if got.Attributes["credential_type"] != tc.wantType {
			t.Errorf("Enrich(%q).Attributes[credential_type] = %q, want %q", tc.kind, got.Attributes["credential_type"], tc.wantType)
		}
		if got.CredentialID != cred.ID {
			t.Errorf("CredentialID = %q, want %q", got.CredentialID, cred.ID)
		}
		if got.Source == "" {
			t.Error("Source must not be empty")
		}
		if got.Confidence <= 0 || got.Confidence > 1 {
			t.Errorf("Confidence = %.2f, want in (0, 1]", got.Confidence)
		}
	}
}

func TestEnrich_UnknownRuleIDStillReturnsLowConfidenceResult(t *testing.T) {
	e := aws.New()

	got, err := e.Enrich(context.Background(), cerberus.Credential{ID: "cred_1", Provider: "aws", Kind: "aws-something-new"})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got.CredentialType != "" {
		t.Errorf("unknown rule ID should not be classified, got CredentialType=%q", got.CredentialType)
	}
	if got.Confidence <= 0 {
		t.Error("Confidence should still be positive (Provider/Kind pass-through is honest, if low-value)")
	}
}

// TestEnrich_DoesNotClaimKeyClass documents, in a runnable assertion,
// the scope boundary explained in the aws package doc comment: this
// enricher must never claim to distinguish AWS access-key classes
// (e.g. long-term "AKIA" vs. temporary "ASIA") because
// cerberus.Credential does not retain the MaskedPrefix data that
// distinction would require.
func TestEnrich_DoesNotClaimKeyClass(t *testing.T) {
	e := aws.New()

	got, err := e.Enrich(context.Background(), cerberus.Credential{ID: "cred_1", Provider: "aws", Kind: "aws-access-key-id"})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if _, ok := got.Attributes["key_class"]; ok {
		t.Error("this enricher must not report key_class — see the package doc comment for why")
	}
}
