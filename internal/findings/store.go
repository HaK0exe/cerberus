// Package findings defines the Finding persistence contract and an
// in-memory implementation for local/CLI use. Cloud deployments back
// this with DynamoDB (see internal/storage).
package findings

import (
	"context"
	"fmt"
	"sync"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// Store persists and queries Findings. It never accepts or returns raw
// secret values — only what cerberus.Finding already carries.
type Store interface {
	Put(ctx context.Context, f cerberus.Finding) error
	Get(ctx context.Context, id string) (cerberus.Finding, error)
	List(ctx context.Context, filter Filter) ([]cerberus.Finding, error)
}

// Filter narrows a List call. Zero values mean "no filter".
type Filter struct {
	State      cerberus.State
	SourceType cerberus.SourceType
	RuleID     string
	Limit      int
}

// MemStore is an in-memory Store, suitable for the CLI and tests.
type MemStore struct {
	mu   sync.RWMutex
	data map[string]cerberus.Finding
}

func NewMemStore() *MemStore {
	return &MemStore{data: make(map[string]cerberus.Finding)}
}

func (s *MemStore) Put(_ context.Context, f cerberus.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[f.ID] = f
	return nil
}

func (s *MemStore) Get(_ context.Context, id string) (cerberus.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.data[id]
	if !ok {
		return cerberus.Finding{}, fmt.Errorf("finding %q not found", id)
	}
	return f, nil
}

func (s *MemStore) List(_ context.Context, filter Filter) ([]cerberus.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []cerberus.Finding
	for _, f := range s.data {
		if filter.State != "" && f.State != filter.State {
			continue
		}
		if filter.SourceType != "" && f.SourceType != filter.SourceType {
			continue
		}
		if filter.RuleID != "" && f.RuleID != filter.RuleID {
			continue
		}
		out = append(out, f)
		if filter.Limit > 0 && len(out) >= filter.Limit {
			break
		}
	}
	return out, nil
}
