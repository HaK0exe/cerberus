package git

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// maxFileSize bounds how large a single blob we will read into memory
// for scanning. Larger files are skipped rather than risking unbounded
// memory use on a crafted or accidental huge file.
const maxFileSize = 20 * 1024 * 1024 // 20MB

// NativeGitScanner implements GitScanner by shelling out to the `git`
// binary (assumed present on PATH) rather than reimplementing Git's
// object model. This trades a runtime dependency on `git` for a much
// smaller, more reliably-correct implementation than re-deriving
// index/tree/diff semantics via a pure-Go Git library.
type NativeGitScanner struct {
	// GitBin overrides the git binary used; defaults to "git" if empty.
	GitBin string
}

func NewNative() *NativeGitScanner { return &NativeGitScanner{} }

func (s *NativeGitScanner) bin() string {
	if s.GitBin != "" {
		return s.GitBin
	}
	return "git"
}

func (s *NativeGitScanner) run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, s.bin(), args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (s *NativeGitScanner) Scan(ctx context.Context, repo Repository, opts cerberus.ScanOptions) (<-chan cerberus.Artifact, error) {
	switch repo.Mode {
	case ModeWorkingTree, "":
		return s.scanWorkingTree(ctx, repo)
	case ModeStaged:
		return s.scanStaged(ctx, repo)
	case ModeCommit, ModeBranch:
		return s.scanRef(ctx, repo, repo.Ref)
	case ModeFullHistory:
		return s.scanFullHistory(ctx, repo)
	default:
		return nil, fmt.Errorf("git scanner: unknown mode %q", repo.Mode)
	}
}

// scanWorkingTree lists every tracked-or-untracked-but-not-ignored file
// (i.e. `git ls-files --cached --others --exclude-standard`, which
// applies .gitignore for us) and reads it straight off disk.
func (s *NativeGitScanner) scanWorkingTree(ctx context.Context, repo Repository) (<-chan cerberus.Artifact, error) {
	out, err := s.run(ctx, repo.Path, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, fmt.Errorf("listing working tree files: %w", err)
	}
	paths := splitNUL(out)

	ch := make(chan cerberus.Artifact)
	go func() {
		defer close(ch)
		for _, rel := range paths {
			select {
			case <-ctx.Done():
				return
			default:
			}
			abs := filepath.Join(repo.Path, rel)
			info, err := os.Lstat(abs)
			if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileSize {
				continue
			}
			content, err := os.ReadFile(abs)
			if err != nil || looksBinary(content) {
				continue
			}
			send(ctx, ch, cerberus.Artifact{
				ID:         "worktree:" + rel,
				SourceType: cerberus.SourceGitWorkingTree,
				Path:       rel,
				Content:    content,
				FetchedAt:  time.Now().UTC(),
			})
		}
	}()
	return ch, nil
}

// scanStaged reads the index (staged) version of every staged file via
// `git show :<path>`, not the working-tree file — so unstaged edits on
// top of a staged secret are correctly ignored.
func (s *NativeGitScanner) scanStaged(ctx context.Context, repo Repository) (<-chan cerberus.Artifact, error) {
	out, err := s.run(ctx, repo.Path, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
	if err != nil {
		return nil, fmt.Errorf("listing staged files: %w", err)
	}
	paths := splitNUL(out)

	ch := make(chan cerberus.Artifact)
	go func() {
		defer close(ch)
		for _, rel := range paths {
			select {
			case <-ctx.Done():
				return
			default:
			}
			content, err := s.run(ctx, repo.Path, "show", ":"+rel)
			if err != nil || len(content) > maxFileSize || looksBinary(content) {
				continue
			}
			send(ctx, ch, cerberus.Artifact{
				ID:         "staged:" + rel,
				SourceType: cerberus.SourceGitStaged,
				Path:       rel,
				Content:    content,
				FetchedAt:  time.Now().UTC(),
			})
		}
	}()
	return ch, nil
}

// scanRef scans every file in the tree at ref (a commit SHA or branch
// name), used for ModeCommit and ModeBranch.
func (s *NativeGitScanner) scanRef(ctx context.Context, repo Repository, ref string) (<-chan cerberus.Artifact, error) {
	if ref == "" {
		return nil, fmt.Errorf("git scanner: mode %q requires a ref", repo.Mode)
	}
	sha, err := s.resolveRef(ctx, repo.Path, ref)
	if err != nil {
		return nil, err
	}

	out, err := s.run(ctx, repo.Path, "ls-tree", "-r", "--name-only", "-z", sha)
	if err != nil {
		return nil, fmt.Errorf("listing tree at %s: %w", ref, err)
	}
	paths := splitNUL(out)

	ch := make(chan cerberus.Artifact)
	go func() {
		defer close(ch)
		for _, rel := range paths {
			select {
			case <-ctx.Done():
				return
			default:
			}
			content, err := s.run(ctx, repo.Path, "show", sha+":"+rel)
			if err != nil || len(content) > maxFileSize || looksBinary(content) {
				continue
			}
			send(ctx, ch, cerberus.Artifact{
				ID:         "commit:" + sha + ":" + rel,
				SourceType: cerberus.SourceGitCommit,
				Path:       rel,
				Commit:     sha,
				Content:    content,
				FetchedAt:  time.Now().UTC(),
			})
		}
	}()
	return ch, nil
}

// scanFullHistory walks every commit reachable from any ref and emits
// an Artifact for each file *changed* in that commit (not the full
// tree every time), so cost is proportional to history size rather
// than history-size × tree-size.
//
// TODO(S2-03 follow-up): this is a native git-log walk, not a
// github.com/gitleaks/gitleaks-as-library integration as originally
// scoped — gitleaks does not currently expose a stable embeddable API
// (its detection engine is built around its own CLI/config pipeline).
// Revisit vendoring gitleaks if its Go API stabilizes; until then this
// gives full-history coverage using the same primitives as the other
// modes.
func (s *NativeGitScanner) scanFullHistory(ctx context.Context, repo Repository) (<-chan cerberus.Artifact, error) {
	out, err := s.run(ctx, repo.Path, "rev-list", "--all")
	if err != nil {
		return nil, fmt.Errorf("listing commits: %w", err)
	}
	commits := splitLines(out)

	ch := make(chan cerberus.Artifact)
	go func() {
		defer close(ch)
		for _, sha := range commits {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// --root is required or `diff-tree` reports no changes for
			// a repository's first (parentless) commit.
			changed, err := s.run(ctx, repo.Path, "diff-tree", "--no-commit-id", "--name-only", "-r", "--root", sha)
			if err != nil {
				continue
			}
			for _, rel := range splitLines(changed) {
				select {
				case <-ctx.Done():
					return
				default:
				}
				content, err := s.run(ctx, repo.Path, "show", sha+":"+rel)
				if err != nil || len(content) > maxFileSize || looksBinary(content) {
					continue
				}
				send(ctx, ch, cerberus.Artifact{
					ID:         "history:" + sha + ":" + rel,
					SourceType: cerberus.SourceGitCommit,
					Path:       rel,
					Commit:     sha,
					Content:    content,
					FetchedAt:  time.Now().UTC(),
				})
			}
		}
	}()
	return ch, nil
}

func (s *NativeGitScanner) resolveRef(ctx context.Context, dir, ref string) (string, error) {
	out, err := s.run(ctx, dir, "rev-parse", "--verify", ref)
	if err != nil {
		return "", fmt.Errorf("resolving ref %q: %w", ref, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func send(ctx context.Context, ch chan<- cerberus.Artifact, a cerberus.Artifact) {
	select {
	case ch <- a:
	case <-ctx.Done():
	}
}

func splitNUL(out []byte) []string {
	out = bytes.TrimSuffix(out, []byte{0})
	if len(out) == 0 {
		return nil
	}
	parts := bytes.Split(out, []byte{0})
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) > 0 {
			result = append(result, string(p))
		}
	}
	return result
}

func splitLines(out []byte) []string {
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// looksBinary applies the same "NUL byte in the first 8000 bytes"
// heuristic Git itself uses to decide whether a blob is binary.
func looksBinary(content []byte) bool {
	n := len(content)
	if n > 8000 {
		n = 8000
	}
	return bytes.IndexByte(content[:n], 0) != -1
}
