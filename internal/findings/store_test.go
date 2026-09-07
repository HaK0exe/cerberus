package findings

import (
	"context"
	"testing"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func mkFinding(id string) cerberus.Finding {
	return cerberus.Finding{ID: id, RuleID: "r", State: cerberus.StateOpen}
}

func TestMemStore_DeterministicListWithLimit(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()
	for _, id := range []string{"f3", "f1", "f2"} {
		if err := s.Put(ctx, mkFinding(id)); err != nil {
			t.Fatal(err)
		}
	}
	first, _ := s.List(ctx, Filter{Limit: 2})
	second, _ := s.List(ctx, Filter{Limit: 2})
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("expected 2 results, got %d/%d", len(first), len(second))
	}
	for i := range first {
		if first[i].ID != second[i].ID {
			t.Fatal("List order must be deterministic across calls")
		}
	}
	if first[0].ID != "f1" || first[1].ID != "f2" {
		t.Fatalf("expected sorted [f1 f2], got [%s %s]", first[0].ID, first[1].ID)
	}
}

func TestMemStore_FilterAndGet(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()
	f := mkFinding("f1")
	f.State = cerberus.StateConfirmed
	_ = s.Put(ctx, f)
	_ = s.Put(ctx, mkFinding("f2"))

	open, _ := s.List(ctx, Filter{State: cerberus.StateOpen})
	if len(open) != 1 || open[0].ID != "f2" {
		t.Fatalf("state filter broken: %+v", open)
	}
	if _, err := s.Get(ctx, "missing"); err == nil {
		t.Error("expected Get on missing id to error")
	}
}
