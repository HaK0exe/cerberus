// Package aws implements an offline, structural CredentialEnricher for
// AWS credentials. It never contacts AWS, never uses the discovered
// credential for anything, and never guesses at facts it cannot derive
// from data already on the cerberus.Credential — see
// docs/adr/0007-credential-intelligence.md for exactly what that
// restricts this enricher to today, and why.
package aws

import (
	"context"
	"time"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

const source = "aws-structural"

// credentialTypes maps the rule IDs rules/cloud/*.yaml currently
// defines for AWS onto a stable, provider-neutral CredentialType.
// cerberus.Credential.Kind is set from the matching rule's ID (see
// internal/detector.Detect and internal/credentials.Correlate), so
// this is the only per-credential signal this enricher has to work
// with beyond Provider — see the package doc and the ADR for why
// finer classification (e.g. long-term vs. temporary access keys)
// is NOT attempted here.
var credentialTypes = map[string]string{
	"aws-access-key-id":     "access_key_id",
	"aws-secret-access-key": "secret_access_key",
}

// Enricher is an offline, structural intelligence.CredentialEnricher
// for AWS credentials.
type Enricher struct{}

// New returns an Enricher. It holds no state and makes no network
// calls.
func New() *Enricher { return &Enricher{} }

// Supports reports whether cred was correlated from an AWS rule.
// internal/credentials.Correlate sets Credential.Provider from the
// text before the first "-" in the matching rule's ID (e.g.
// "aws-access-key-id" -> "aws"), so this must match that exactly.
func (e *Enricher) Supports(cred cerberus.Credential) bool {
	return cred.Provider == "aws"
}

// Enrich derives what's honestly readable from cred's own recorded
// metadata: the AWS credential type behind its Kind (rule ID), and
// nothing else. It never contacts AWS and never uses the discovered
// credential's value.
//
// It intentionally does NOT report a "key_class" (long-term IAM user
// key vs. temporary STS session key), an AWS account ID, or any other
// fact that would require either the credential's own raw value (which
// cerberus.Credential never carries — see docs/adr/0001) or a live
// call against AWS. See the ADR for what a future adapter with an
// authorized, Cerberus-owned IAM/Organizations credential could add
// here, and why the well-known access-key-ID prefix trick (AKIA vs.
// ASIA vs. ...) is not implemented despite being publicly documented:
// cerberus.Credential does not retain the MaskedPrefix that would be
// needed to read it, so implementing it here would either silently
// fall back to guessing or require touching files outside this
// change's scope.
func (e *Enricher) Enrich(_ context.Context, cred cerberus.Credential) (cerberus.Enrichment, error) {
	credType, known := credentialTypes[cred.Kind]

	attrs := map[string]string{
		"rule_id": cred.Kind,
	}

	confidence := 0.15 // this only restates Kind/Provider — see doc comment
	if known {
		attrs["credential_type"] = credType
		confidence = 0.30
	}

	return cerberus.Enrichment{
		CredentialID:   cred.ID,
		Provider:       cred.Provider,
		CredentialType: credType,
		Attributes:     attrs,
		Confidence:     confidence,
		Source:         source,
		EnrichedAt:     time.Now().UTC(),
	}, nil
}
