package credentials

import (
	"context"
	"fmt"
	"sync"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// CredentialStore persists and queries Credentials.
type CredentialStore interface {
	Put(ctx context.Context, c cerberus.Credential) error
	Get(ctx context.Context, id string) (cerberus.Credential, error)
	List(ctx context.Context, filter CredentialFilter) ([]cerberus.Credential, error)
}

// CredentialFilter narrows a CredentialStore.List call. Zero values
// mean "no filter".
type CredentialFilter struct {
	Provider string
	Status   cerberus.CredentialStatus
	Limit    int
}

// ExposureStore persists and queries the Exposures of a Credential.
//
// Method names are distinct from CredentialStore's (rather than an
// overloaded Put/List) so a single implementation such as MemStore can
// satisfy all three store interfaces on one Go type.
type ExposureStore interface {
	PutExposure(ctx context.Context, e cerberus.Exposure) error
	ListByCredential(ctx context.Context, credentialID string) ([]cerberus.Exposure, error)
}

// IncidentStore persists and queries Incidents.
type IncidentStore interface {
	PutIncident(ctx context.Context, i cerberus.Incident) error
	GetIncident(ctx context.Context, id string) (cerberus.Incident, error)
	ListIncidents(ctx context.Context, filter IncidentFilter) ([]cerberus.Incident, error)
}

// IncidentFilter narrows an IncidentStore.List call. Zero values mean
// "no filter".
type IncidentFilter struct {
	Status cerberus.IncidentStatus
	Limit  int
}

// MemStore is an in-memory CredentialStore + ExposureStore +
// IncidentStore, suitable for the CLI and tests. Cloud deployments back
// these contracts with DynamoDB/Postgres (see internal/storage).
type MemStore struct {
	mu sync.RWMutex

	credentials map[string]cerberus.Credential
	exposures   map[string][]cerberus.Exposure // keyed by CredentialID
	incidents   map[string]cerberus.Incident
}

var (
	_ CredentialStore = (*MemStore)(nil)
	_ ExposureStore   = (*MemStore)(nil)
	_ IncidentStore   = (*MemStore)(nil)
)

func NewMemStore() *MemStore {
	return &MemStore{
		credentials: make(map[string]cerberus.Credential),
		exposures:   make(map[string][]cerberus.Exposure),
		incidents:   make(map[string]cerberus.Incident),
	}
}

func (s *MemStore) Put(_ context.Context, c cerberus.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials[c.ID] = c
	return nil
}

func (s *MemStore) Get(_ context.Context, id string) (cerberus.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.credentials[id]
	if !ok {
		return cerberus.Credential{}, fmt.Errorf("credential %q not found", id)
	}
	return c, nil
}

func (s *MemStore) List(_ context.Context, filter CredentialFilter) ([]cerberus.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []cerberus.Credential
	for _, c := range s.credentials {
		if filter.Provider != "" && c.Provider != filter.Provider {
			continue
		}
		if filter.Status != "" && c.Status != filter.Status {
			continue
		}
		out = append(out, c)
		if filter.Limit > 0 && len(out) >= filter.Limit {
			break
		}
	}
	return out, nil
}

func (s *MemStore) PutExposure(_ context.Context, e cerberus.Exposure) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing := s.exposures[e.CredentialID]
	for i, cur := range existing {
		if cur.ID == e.ID {
			existing[i] = e
			return nil
		}
	}
	s.exposures[e.CredentialID] = append(existing, e)
	return nil
}

func (s *MemStore) ListByCredential(_ context.Context, credentialID string) ([]cerberus.Exposure, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]cerberus.Exposure, len(s.exposures[credentialID]))
	copy(out, s.exposures[credentialID])
	return out, nil
}

func (s *MemStore) PutIncident(_ context.Context, i cerberus.Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.incidents[i.ID] = i
	return nil
}

func (s *MemStore) GetIncident(_ context.Context, id string) (cerberus.Incident, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i, ok := s.incidents[id]
	if !ok {
		return cerberus.Incident{}, fmt.Errorf("incident %q not found", id)
	}
	return i, nil
}

func (s *MemStore) ListIncidents(_ context.Context, filter IncidentFilter) ([]cerberus.Incident, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []cerberus.Incident
	for _, i := range s.incidents {
		if filter.Status != "" && i.Status != filter.Status {
			continue
		}
		out = append(out, i)
		if filter.Limit > 0 && len(out) >= filter.Limit {
			break
		}
	}
	return out, nil
}

// PutAll stores the output of Correlate in one call: every Credential,
// Exposure, and Incident. Safe to call repeatedly with a growing
// finding set — Correlate's deterministic IDs make this an upsert.
func (s *MemStore) PutAll(ctx context.Context, creds []cerberus.Credential, exposures []cerberus.Exposure, incidents []cerberus.Incident) error {
	for _, c := range creds {
		if err := s.Put(ctx, c); err != nil {
			return err
		}
	}
	for _, e := range exposures {
		if err := s.PutExposure(ctx, e); err != nil {
			return err
		}
	}
	for _, i := range incidents {
		if err := s.PutIncident(ctx, i); err != nil {
			return err
		}
	}
	return nil
}
