package credentials

import (
	"context"
	"testing"
	"time"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func TestMemStore_PutAllThenQuery(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	findings := []cerberus.Finding{
		mustFinding("fp-a", "aws-access-key-id", "aws_access_key", cerberus.SourceFile, "", "a.env", "", now),
		mustFinding("fp-a", "aws-access-key-id", "aws_access_key", cerberus.SourceFile, "", "b.env", "", now),
		mustFinding("fp-b", "github-pat", "github_pat", cerberus.SourceFile, "", "c.env", "", now),
	}
	creds, exposures, incidents := Correlate(findings)

	store := NewMemStore()
	if err := store.PutAll(ctx, creds, exposures, incidents); err != nil {
		t.Fatalf("PutAll: %v", err)
	}

	all, err := store.List(ctx, CredentialFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("want 2 credentials in store, got %d", len(all))
	}

	got, err := store.Get(ctx, creds[0].ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != creds[0].ID {
		t.Errorf("Get returned %q, want %q", got.ID, creds[0].ID)
	}

	exp, err := store.ListByCredential(ctx, creds[0].ID)
	if err != nil {
		t.Fatalf("ListByCredential: %v", err)
	}
	if len(exp) != 2 {
		t.Errorf("want 2 exposures for %q, got %d", creds[0].ID, len(exp))
	}

	inc, err := store.GetIncident(ctx, incidents[0].ID)
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if inc.CredentialID != creds[0].ID {
		t.Errorf("incident.CredentialID = %q, want %q", inc.CredentialID, creds[0].ID)
	}

	filtered, err := store.List(ctx, CredentialFilter{Provider: "github"})
	if err != nil {
		t.Fatalf("List filtered: %v", err)
	}
	if len(filtered) != 1 || filtered[0].Provider != "github" {
		t.Errorf("provider filter returned %+v", filtered)
	}
}

func TestMemStore_GetMissingReturnsError(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()

	if _, err := store.Get(ctx, "cred_nope"); err == nil {
		t.Error("Get on missing credential should error")
	}
	if _, err := store.GetIncident(ctx, "inc_nope"); err == nil {
		t.Error("GetIncident on missing incident should error")
	}
}

func TestMemStore_PutAllIsIdempotent(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	findings := []cerberus.Finding{
		mustFinding("fp-a", "aws-access-key-id", "aws_access_key", cerberus.SourceFile, "", "a.env", "", now),
	}
	creds, exposures, incidents := Correlate(findings)

	store := NewMemStore()
	if err := store.PutAll(ctx, creds, exposures, incidents); err != nil {
		t.Fatalf("PutAll (1st): %v", err)
	}
	if err := store.PutAll(ctx, creds, exposures, incidents); err != nil {
		t.Fatalf("PutAll (2nd): %v", err)
	}

	all, _ := store.List(ctx, CredentialFilter{})
	if len(all) != 1 {
		t.Fatalf("re-applying the same correlation output should not duplicate credentials, got %d", len(all))
	}
	exp, _ := store.ListByCredential(ctx, creds[0].ID)
	if len(exp) != 1 {
		t.Fatalf("re-applying the same correlation output should not duplicate exposures, got %d", len(exp))
	}
}
