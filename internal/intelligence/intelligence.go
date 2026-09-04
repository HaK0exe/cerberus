// Package intelligence defines the credential-enrichment extension
// point: turning a bare cerberus.Credential (provider, kind, a
// fingerprint, timestamps) into structured cerberus.Enrichment facts,
// and the Registry that dispatches a Credential to whichever
// enrichers support it.
//
// Every CredentialEnricher in this tree — and every adapter under it
// (internal/intelligence/aws, and future github/gcp/vault packages) —
// must be offline and side-effect-free: no network calls, no shelling
// out, nothing that could be mistaken for using the discovered
// credential itself. See docs/adr/0007-credential-intelligence.md.
package intelligence

import (
	"context"
	"errors"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// CredentialEnricher turns a Credential into an Enrichment. Supports
// must be cheap and side-effect-free — Registry calls it on every
// registered enricher for every Credential to decide who runs.
type CredentialEnricher interface {
	Supports(cerberus.Credential) bool
	Enrich(context.Context, cerberus.Credential) (cerberus.Enrichment, error)
}

// Registry holds a set of CredentialEnrichers and dispatches a
// Credential to every one that supports it, so a future GitHub/GCP/
// Vault adapter is a new CredentialEnricher registered here — never a
// change to this package or to callers of EnrichAll.
type Registry struct {
	enrichers []CredentialEnricher
}

// NewRegistry builds a Registry from zero or more enrichers.
func NewRegistry(enrichers ...CredentialEnricher) *Registry {
	return &Registry{enrichers: enrichers}
}

// Register adds an enricher to the registry.
func (r *Registry) Register(e CredentialEnricher) {
	r.enrichers = append(r.enrichers, e)
}

// EnrichAll runs every registered enricher that Supports cred and
// returns their Enrichments in registration order. An enricher that
// errors is skipped — its error is folded into the returned error via
// errors.Join, but the other enrichers' results are still returned, so
// one misbehaving/unavailable enricher doesn't blank out everything
// else known about the Credential.
func (r *Registry) EnrichAll(ctx context.Context, cred cerberus.Credential) ([]cerberus.Enrichment, error) {
	var results []cerberus.Enrichment
	var errs []error

	for _, e := range r.enrichers {
		if !e.Supports(cred) {
			continue
		}
		enrichment, err := e.Enrich(ctx, cred)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		results = append(results, enrichment)
	}

	return results, errors.Join(errs...)
}
