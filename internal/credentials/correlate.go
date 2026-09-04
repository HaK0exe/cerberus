// Package credentials correlates Findings that share an HMAC
// fingerprint into a single Credential with one Exposure per distinct
// location, and groups each Credential's Exposures into an Incident.
//
// This is what lets Cerberus answer "how many unique credentials?" and
// "where else was this one exposed?" instead of treating every Finding
// as an independent incident. See docs/adr/0004-credential-exposure-model.md.
package credentials

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// Correlate groups findings by Fingerprint into Credentials, Exposures,
// and one Incident per Credential. It is pure and deterministic: the
// same finding always maps to the same Credential/Exposure/Incident
// IDs, so re-running correlation over a growing finding set is
// idempotent and safe to merge into a store.
//
// Findings with an empty Fingerprint are skipped — they cannot be
// correlated or deduplicated safely.
func Correlate(findings []cerberus.Finding) ([]cerberus.Credential, []cerberus.Exposure, []cerberus.Incident) {
	type bucket struct {
		cred      cerberus.Credential
		exposures map[string]cerberus.Exposure
	}

	buckets := make(map[string]*bucket)
	var order []string // first-seen fingerprint order, for stable output

	for _, f := range findings {
		if f.Fingerprint == "" {
			continue
		}

		b, ok := buckets[f.Fingerprint]
		if !ok {
			b = &bucket{
				cred: cerberus.Credential{
					ID:          CredentialID(f.Fingerprint),
					Fingerprint: f.Fingerprint,
					Provider:    providerFromRule(f.RuleID),
					Kind:        f.Type,
					FirstSeen:   f.CreatedAt,
					LastSeen:    f.CreatedAt,
					Status:      cerberus.CredentialStatusActive,
				},
				exposures: make(map[string]cerberus.Exposure),
			}
			buckets[f.Fingerprint] = b
			order = append(order, f.Fingerprint)
		}

		if b.cred.FirstSeen.IsZero() || (!f.CreatedAt.IsZero() && f.CreatedAt.Before(b.cred.FirstSeen)) {
			b.cred.FirstSeen = f.CreatedAt
		}
		if f.CreatedAt.After(b.cred.LastSeen) {
			b.cred.LastSeen = f.CreatedAt
		}

		expID := ExposureID(b.cred.ID, f.SourceType, f.SourceURI, f.Path, f.Commit)
		exp, exists := b.exposures[expID]
		if !exists {
			exp = cerberus.Exposure{
				ID:           expID,
				CredentialID: b.cred.ID,
				SourceType:   f.SourceType,
				SourceURI:    f.SourceURI,
				Path:         f.Path,
				Commit:       f.Commit,
				FirstSeen:    f.CreatedAt,
				LastSeen:     f.CreatedAt,
			}
		} else {
			if !f.CreatedAt.IsZero() && f.CreatedAt.Before(exp.FirstSeen) {
				exp.FirstSeen = f.CreatedAt
			}
			if f.CreatedAt.After(exp.LastSeen) {
				exp.LastSeen = f.CreatedAt
			}
		}
		b.exposures[expID] = exp
	}

	var credentialsOut []cerberus.Credential
	var exposuresOut []cerberus.Exposure
	var incidentsOut []cerberus.Incident

	for _, fp := range order {
		b := buckets[fp]
		b.cred.ExposureCount = len(b.exposures)
		credentialsOut = append(credentialsOut, b.cred)

		var expIDs []string
		for _, exp := range b.exposures {
			exposuresOut = append(exposuresOut, exp)
			expIDs = append(expIDs, exp.ID)
		}
		sort.Strings(expIDs) // deterministic regardless of map iteration order

		incidentsOut = append(incidentsOut, cerberus.Incident{
			ID:           IncidentID(b.cred.ID),
			CredentialID: b.cred.ID,
			ExposureIDs:  expIDs,
			Status:       cerberus.IncidentStatusOpen,
			CreatedAt:    b.cred.FirstSeen,
			UpdatedAt:    b.cred.LastSeen,
		})
	}

	return credentialsOut, exposuresOut, incidentsOut
}

// CredentialID derives a stable, deterministic Credential ID from a
// Finding's fingerprint, so re-correlating the same secret always
// yields the same Credential. It is a one-way derivation, not the
// fingerprint itself: neither value is ever reversible back to the raw
// secret, but the ID and the fingerprint are still kept distinct so
// the fingerprint's own derivation (see internal/policy) stays the
// single source of truth for "is this the same secret".
func CredentialID(fingerprint string) string {
	sum := sha256.Sum256([]byte("credential:" + fingerprint))
	return "cred_" + hex.EncodeToString(sum[:])[:16]
}

// ExposureID derives a stable, deterministic Exposure ID from the
// credential it belongs to plus its distinct location, so the same
// (credential, location) pair always correlates to the same Exposure.
func ExposureID(credentialID string, sourceType cerberus.SourceType, sourceURI, path, commit string) string {
	sum := sha256.Sum256([]byte("exposure:" + credentialID + "|" + string(sourceType) + "|" + sourceURI + "|" + path + "|" + commit))
	return "exp_" + hex.EncodeToString(sum[:])[:16]
}

// IncidentID derives a stable, deterministic Incident ID for a
// Credential. The correlation service keeps a 1:1 Incident<->Credential
// mapping today.
func IncidentID(credentialID string) string {
	sum := sha256.Sum256([]byte("incident:" + credentialID))
	return "inc_" + hex.EncodeToString(sum[:])[:16]
}

// providerFromRule makes a best-effort guess at the credential provider
// family from a rule ID such as "aws-access-key-id" or "github-pat".
func providerFromRule(ruleID string) string {
	if i := strings.IndexByte(ruleID, '-'); i > 0 {
		return ruleID[:i]
	}
	return ruleID
}
