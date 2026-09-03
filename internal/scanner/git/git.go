// Package git implements cerberus scanner.Scanner for Git repositories:
// working tree, staged files, a single commit/branch, and full history.
//
// Sprint 2 will add two implementations behind the GitScanner
// interface: GitleaksScanner (wraps github.com/gitleaks/gitleaks as a
// library for history walking) and NativeGitScanner (go-git based).
// Gitleaks types must never leak into pkg/cerberus — adapt at the
// boundary.
package git

import (
	"context"
	"errors"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// GitScanner is the Git-specific scanning contract (kept distinct from
// the generic scanner.Scanner so implementations can expose git-only
// options like Mode).
type GitScanner interface {
	Scan(ctx context.Context, repo Repository, opts cerberus.ScanOptions) (<-chan cerberus.Artifact, error)
}

// Mode selects which part of a repository to scan.
type Mode string

const (
	ModeWorkingTree Mode = "working-tree"
	ModeStaged      Mode = "staged"
	ModeCommit      Mode = "commit"
	ModeBranch      Mode = "branch"
	ModeFullHistory Mode = "full-history"
)

// Repository identifies a local Git repository to scan.
type Repository struct {
	Path string
	Mode Mode
	Ref  string // commit SHA or branch name, depending on Mode
}

// ErrNotImplemented is returned by scaffold-stage scanners.
// TODO(sprint-2): replace with GitleaksScanner / NativeGitScanner.
var ErrNotImplemented = errors.New("git scanner: not implemented yet (see Sprint 2)")

type notImplementedScanner struct{}

func New() GitScanner { return notImplementedScanner{} }

func (notImplementedScanner) Scan(context.Context, Repository, cerberus.ScanOptions) (<-chan cerberus.Artifact, error) {
	return nil, ErrNotImplemented
}
