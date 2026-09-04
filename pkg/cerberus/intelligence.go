package cerberus

import "time"

// Enrichment is the structured output of a CredentialEnricher: what can
// be honestly determined about a Credential from data already on hand
// (its own recorded metadata) or from an authorized, Cerberus-owned
// lookup — never from probing the credential against the service it
// belongs to. See docs/adr/0007-credential-intelligence.md.
//
// Deliberately absent: any field implying live validation happened
// (no "IsValid", no "IsActive"). An Enrichment only ever states facts
// an enricher can stand behind without having authenticated as the
// credential itself.
type Enrichment struct {
	CredentialID string

	Provider       string
	CredentialType string

	// Attributes is the open-ended bag for provider-specific structural
	// facts (e.g. "key_class": "access_key_id" for AWS). Each key is
	// namespaced by the enricher that set it and should be documented
	// at the call site — this package makes no claim about which keys
	// exist.
	Attributes map[string]string

	// Confidence reflects how much this Enrichment actually adds beyond
	// what was already known about the Credential, in [0, 1]. An
	// enricher that can only restate Credential.Provider/Kind back at
	// the caller should report a low Confidence, not a high one.
	Confidence float64

	// Source names the enricher that produced this Enrichment (e.g.
	// "aws-structural") — see CredentialEnricher in
	// internal/intelligence.
	Source string

	EnrichedAt time.Time
}
