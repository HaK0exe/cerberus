package credentials

import (
	"testing"
	"time"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func mustFinding(fingerprint, ruleID, typ string, source cerberus.SourceType, uri, path, commit string, at time.Time) cerberus.Finding {
	return cerberus.Finding{
		ID:          "fnd_" + fingerprint + "_" + path,
		RuleID:      ruleID,
		Type:        typ,
		Fingerprint: fingerprint,
		SourceType:  source,
		SourceURI:   uri,
		Path:        path,
		Commit:      commit,
		CreatedAt:   at,
	}
}

func TestCorrelate_SameFingerprintDifferentLocationsGroupIntoOneCredential(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(24 * time.Hour)

	findings := []cerberus.Finding{
		mustFinding("fp-a", "aws-access-key-id", "aws_access_key", cerberus.SourceGitCommit, "repo1", "a.env", "c1", t0),
		mustFinding("fp-a", "aws-access-key-id", "aws_access_key", cerberus.SourceGitCommit, "repo1", "b.env", "c2", t1),
		mustFinding("fp-a", "aws-access-key-id", "aws_access_key", cerberus.SourceWebPage, "https://example.com/x.js", "x.js", "", t1),
	}

	creds, exposures, incidents := Correlate(findings)

	if len(creds) != 1 {
		t.Fatalf("want 1 credential, got %d", len(creds))
	}
	c := creds[0]
	if c.ExposureCount != 3 {
		t.Errorf("want 3 exposures, got %d", c.ExposureCount)
	}
	if !c.FirstSeen.Equal(t0) {
		t.Errorf("FirstSeen = %v, want %v", c.FirstSeen, t0)
	}
	if !c.LastSeen.Equal(t1) {
		t.Errorf("LastSeen = %v, want %v", c.LastSeen, t1)
	}
	if c.Provider != "aws" {
		t.Errorf("Provider = %q, want %q", c.Provider, "aws")
	}
	if len(exposures) != 3 {
		t.Errorf("want 3 exposures total, got %d", len(exposures))
	}
	if len(incidents) != 1 {
		t.Fatalf("want 1 incident, got %d", len(incidents))
	}
	if incidents[0].CredentialID != c.ID {
		t.Errorf("incident.CredentialID = %q, want %q", incidents[0].CredentialID, c.ID)
	}
	if len(incidents[0].ExposureIDs) != 3 {
		t.Errorf("incident has %d exposure IDs, want 3", len(incidents[0].ExposureIDs))
	}
}

func TestCorrelate_DifferentFingerprintsProduceSeparateCredentials(t *testing.T) {
	now := time.Now()
	findings := []cerberus.Finding{
		mustFinding("fp-a", "aws-access-key-id", "aws_access_key", cerberus.SourceFile, "", "a.env", "", now),
		mustFinding("fp-b", "github-pat", "github_pat", cerberus.SourceFile, "", "b.env", "", now),
	}

	creds, _, incidents := Correlate(findings)

	if len(creds) != 2 {
		t.Fatalf("want 2 credentials, got %d", len(creds))
	}
	if len(incidents) != 2 {
		t.Fatalf("want 2 incidents, got %d", len(incidents))
	}
	if creds[0].ID == creds[1].ID {
		t.Errorf("distinct fingerprints must not collide onto the same credential ID: %q", creds[0].ID)
	}
}

func TestCorrelate_SameLocationRepeatedDoesNotDuplicateExposure(t *testing.T) {
	now := time.Now()
	findings := []cerberus.Finding{
		mustFinding("fp-a", "aws-access-key-id", "aws_access_key", cerberus.SourceFile, "", "a.env", "", now),
		mustFinding("fp-a", "aws-access-key-id", "aws_access_key", cerberus.SourceFile, "", "a.env", "", now.Add(time.Hour)),
	}

	creds, exposures, _ := Correlate(findings)

	if len(creds) != 1 || creds[0].ExposureCount != 1 {
		t.Fatalf("want 1 credential with 1 exposure, got %+v", creds)
	}
	if len(exposures) != 1 {
		t.Fatalf("want 1 exposure, got %d", len(exposures))
	}
}

func TestCorrelate_EmptyFingerprintIsSkipped(t *testing.T) {
	findings := []cerberus.Finding{
		{ID: "fnd_1", Fingerprint: "", Path: "a.env"},
	}

	creds, exposures, incidents := Correlate(findings)
	if len(creds) != 0 || len(exposures) != 0 || len(incidents) != 0 {
		t.Fatalf("findings with no fingerprint must be skipped, got creds=%d exposures=%d incidents=%d",
			len(creds), len(exposures), len(incidents))
	}
}

func TestCorrelate_IsDeterministicAndIdempotent(t *testing.T) {
	now := time.Now()
	findings := []cerberus.Finding{
		mustFinding("fp-a", "aws-access-key-id", "aws_access_key", cerberus.SourceFile, "", "a.env", "", now),
	}

	creds1, exp1, inc1 := Correlate(findings)
	creds2, exp2, inc2 := Correlate(findings)

	if creds1[0].ID != creds2[0].ID {
		t.Errorf("credential ID not stable across runs: %q vs %q", creds1[0].ID, creds2[0].ID)
	}
	if exp1[0].ID != exp2[0].ID {
		t.Errorf("exposure ID not stable across runs: %q vs %q", exp1[0].ID, exp2[0].ID)
	}
	if inc1[0].ID != inc2[0].ID {
		t.Errorf("incident ID not stable across runs: %q vs %q", inc1[0].ID, inc2[0].ID)
	}
}

// TestCredentialID_NoCollisionsOverManyFingerprints is a lightweight
// collision sanity check for the truncated-hash ID scheme: a large set
// of distinct synthetic fingerprints must map to distinct IDs.
func TestCredentialID_NoCollisionsOverManyFingerprints(t *testing.T) {
	seen := make(map[string]string, 5000)
	for i := 0; i < 5000; i++ {
		fp := "cerberus:hmac-sha256:" + randHex(i)
		id := CredentialID(fp)
		if prev, ok := seen[id]; ok && prev != fp {
			t.Fatalf("collision: fingerprints %q and %q both map to %q", prev, fp, id)
		}
		seen[id] = fp
	}
}

func TestExposureID_DistinctLocationsProduceDistinctIDs(t *testing.T) {
	id1 := ExposureID("cred_x", cerberus.SourceFile, "", "a.env", "")
	id2 := ExposureID("cred_x", cerberus.SourceFile, "", "b.env", "")
	id3 := ExposureID("cred_x", cerberus.SourceGitCommit, "", "a.env", "c1")

	if id1 == id2 || id1 == id3 || id2 == id3 {
		t.Fatalf("distinct locations must not collide: %q %q %q", id1, id2, id3)
	}
	if id1 != ExposureID("cred_x", cerberus.SourceFile, "", "a.env", "") {
		t.Errorf("ExposureID is not deterministic for identical inputs")
	}
}

func randHex(seed int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 64)
	x := uint64(seed*2654435761 + 1)
	for i := range b {
		x = x*6364136223846793005 + 1442695040888963407
		b[i] = hex[(x>>33)&0xF]
	}
	return string(b)
}
