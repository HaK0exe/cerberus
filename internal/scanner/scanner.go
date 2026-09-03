// Package scanner defines the shared scanning contracts implemented by
// internal/scanner/git and internal/scanner/web. A scanner's only job
// is to produce cerberus.Artifact values on a channel — it never runs
// detection itself and holds no remediation permissions.
package scanner

import (
	"context"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// Scanner produces Artifacts for a target (a repository, a URL, a
// directory, ...).
type Scanner interface {
	Scan(ctx context.Context, target string, opts cerberus.ScanOptions) (<-chan cerberus.Artifact, error)
}
