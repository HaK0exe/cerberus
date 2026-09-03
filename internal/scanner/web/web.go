// Package web implements a colly-based web crawler that emits
// cerberus.Artifact for HTML pages, inline scripts, and linked
// JavaScript. Sprint 2.
//
// SECURITY: every implementation in this package MUST route outbound
// requests through internal/scanner/web/ssrf (Sprint 2) — DNS
// resolution, IP validation (blocking RFC1918/link-local/loopback and
// 169.254.169.254), and re-validation on every redirect hop. See
// docs/security/ssrf.md. Do not add an HTTP client here that bypasses
// that guard.
package web

import (
	"context"
	"errors"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// ErrNotImplemented is returned by the scaffold-stage crawler.
// TODO(sprint-2): implement Colly-based crawler with SSRF guard,
// robots.txt handling, scope/depth limits, and JS extraction.
var ErrNotImplemented = errors.New("web scanner: not implemented yet (see Sprint 2)")

type notImplementedScanner struct{}

func New() *notImplementedScanner { return &notImplementedScanner{} }

func (*notImplementedScanner) Scan(context.Context, string, cerberus.ScanOptions) (<-chan cerberus.Artifact, error) {
	return nil, ErrNotImplemented
}
