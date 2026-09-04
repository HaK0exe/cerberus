package intelligence_test

import (
	"context"
	"errors"
	"testing"

	"github.com/HaK0exe/cerberus/internal/intelligence"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

type stubEnricher struct {
	name      string
	supports  func(cerberus.Credential) bool
	enrich    func(cerberus.Credential) (cerberus.Enrichment, error)
	callCount int
}

func (s *stubEnricher) Supports(c cerberus.Credential) bool { return s.supports(c) }

func (s *stubEnricher) Enrich(_ context.Context, c cerberus.Credential) (cerberus.Enrichment, error) {
	s.callCount++
	return s.enrich(c)
}

func TestRegistry_DispatchesOnlyToSupportingEnrichers(t *testing.T) {
	aws := &stubEnricher{
		name:     "aws",
		supports: func(c cerberus.Credential) bool { return c.Provider == "aws" },
		enrich: func(c cerberus.Credential) (cerberus.Enrichment, error) {
			return cerberus.Enrichment{CredentialID: c.ID, Source: "aws"}, nil
		},
	}
	github := &stubEnricher{
		name:     "github",
		supports: func(c cerberus.Credential) bool { return c.Provider == "github" },
		enrich: func(c cerberus.Credential) (cerberus.Enrichment, error) {
			return cerberus.Enrichment{CredentialID: c.ID, Source: "github"}, nil
		},
	}

	reg := intelligence.NewRegistry(aws, github)

	results, err := reg.EnrichAll(context.Background(), cerberus.Credential{ID: "cred_1", Provider: "aws"})
	if err != nil {
		t.Fatalf("EnrichAll: %v", err)
	}
	if len(results) != 1 || results[0].Source != "aws" {
		t.Fatalf("want only the aws enricher to run, got %+v", results)
	}
	if aws.callCount != 1 {
		t.Errorf("aws enricher called %d times, want 1", aws.callCount)
	}
	if github.callCount != 0 {
		t.Errorf("github enricher called %d times, want 0 (Supports should have skipped it)", github.callCount)
	}
}

func TestRegistry_NoSupportingEnricherReturnsEmpty(t *testing.T) {
	reg := intelligence.NewRegistry(&stubEnricher{
		supports: func(cerberus.Credential) bool { return false },
	})

	results, err := reg.EnrichAll(context.Background(), cerberus.Credential{ID: "cred_1", Provider: "stripe"})
	if err != nil {
		t.Fatalf("EnrichAll: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("want no results, got %+v", results)
	}
}

func TestRegistry_OneEnricherErrorDoesNotBlankOthers(t *testing.T) {
	failing := &stubEnricher{
		supports: func(cerberus.Credential) bool { return true },
		enrich: func(cerberus.Credential) (cerberus.Enrichment, error) {
			return cerberus.Enrichment{}, errors.New("boom")
		},
	}
	ok := &stubEnricher{
		supports: func(cerberus.Credential) bool { return true },
		enrich: func(c cerberus.Credential) (cerberus.Enrichment, error) {
			return cerberus.Enrichment{CredentialID: c.ID, Source: "ok"}, nil
		},
	}

	reg := intelligence.NewRegistry(failing, ok)
	results, err := reg.EnrichAll(context.Background(), cerberus.Credential{ID: "cred_1"})

	if err == nil {
		t.Error("expected a non-nil error from the failing enricher")
	}
	if len(results) != 1 || results[0].Source != "ok" {
		t.Errorf("expected the successful enricher's result to survive, got %+v", results)
	}
}

func TestRegistry_RegisterAddsAnEnricher(t *testing.T) {
	reg := intelligence.NewRegistry()
	reg.Register(&stubEnricher{
		supports: func(cerberus.Credential) bool { return true },
		enrich: func(c cerberus.Credential) (cerberus.Enrichment, error) {
			return cerberus.Enrichment{CredentialID: c.ID, Source: "late"}, nil
		},
	})

	results, err := reg.EnrichAll(context.Background(), cerberus.Credential{ID: "cred_1"})
	if err != nil {
		t.Fatalf("EnrichAll: %v", err)
	}
	if len(results) != 1 || results[0].Source != "late" {
		t.Errorf("registered enricher did not run, got %+v", results)
	}
}
