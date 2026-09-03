// Package audit implements the append-only audit trail for sensitive
// operations (remediation approval/execution, scope changes, RBAC
// changes). See docs/security/audit.md.
package audit

import (
	"context"
	"time"
)

// Event is a single append-only audit record. Never include secret
// values, authorization headers, or credentials in Metadata.
type Event struct {
	Actor     string
	Action    string
	Resource  string
	Result    string
	RequestID string
	Timestamp time.Time
	Metadata  map[string]string
}

// Sink persists audit Events. Implementations must be append-only:
// no update or delete path is exposed on this interface by design.
type Sink interface {
	Record(ctx context.Context, e Event) error
}

// NopSink discards events. Used only where audit is explicitly
// disabled (e.g. unit tests) — never as a production default.
type NopSink struct{}

func (NopSink) Record(context.Context, Event) error { return nil }
