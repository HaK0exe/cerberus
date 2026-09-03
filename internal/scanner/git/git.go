// Package git implements cerberus scanner.Scanner for Git repositories:
// working tree, staged files, a single commit/branch, and full history.
//
// NativeGitScanner (native.go) shells out to the git binary for all
// five modes, including full history — see the TODO on
// NativeGitScanner.scanFullHistory for why this superseded the
// originally-scoped gitleaks-as-library approach.
package git

import (
	"context"

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

// New returns the default GitScanner implementation (NativeGitScanner).
func New() GitScanner { return NewNative() }
