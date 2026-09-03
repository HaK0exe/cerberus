package git_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	gitscanner "github.com/HaK0exe/cerberus/internal/scanner/git"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// testRepo creates a throwaway Git repository with:
//   - a first commit containing secret.env with an AWS key (root commit,
//     to also exercise the --root full-history edge case)
//   - a second commit that removes the secret (so working-tree/HEAD no
//     longer contain it, but history does)
//   - a staged-but-uncommitted change to staged.env containing a
//     different AWS key
//   - an unstaged, untracked file unstaged.env containing a third key,
//     which must NOT show up in staged/commit/history scans
func testRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	run("init", "-q", "-b", "main")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "test")

	writeFile(t, dir, "secret.env", "aws_access_key_id = AKIAAAAAAAAAAAAAAAA1\n")
	run("add", "secret.env")
	run("commit", "-q", "-m", "add secret")

	writeFile(t, dir, "secret.env", "# secret removed\n")
	run("add", "secret.env")
	run("commit", "-q", "-m", "remove secret")

	writeFile(t, dir, "staged.env", "aws_access_key_id = AKIABBBBBBBBBBBBBBBB2\n")
	run("add", "staged.env")

	writeFile(t, dir, "unstaged.env", "aws_access_key_id = AKIACCCCCCCCCCCCCCCC3\n")

	return dir
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func collect(t *testing.T, ch <-chan cerberus.Artifact) []cerberus.Artifact {
	t.Helper()
	var out []cerberus.Artifact
	for a := range ch {
		out = append(out, a)
	}
	return out
}

func TestNativeGitScanner_WorkingTree(t *testing.T) {
	dir := testRepo(t)
	s := gitscanner.NewNative()

	ch, err := s.Scan(context.Background(), gitscanner.Repository{Path: dir, Mode: gitscanner.ModeWorkingTree}, cerberus.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	artifacts := collect(t, ch)

	paths := map[string]bool{}
	for _, a := range artifacts {
		paths[a.Path] = true
		if a.SourceType != cerberus.SourceGitWorkingTree {
			t.Errorf("unexpected SourceType %q for %s", a.SourceType, a.Path)
		}
	}
	// secret.env (post-removal content), staged.env, and unstaged.env
	// are all present on disk regardless of Git state.
	for _, want := range []string{"secret.env", "staged.env", "unstaged.env"} {
		if !paths[want] {
			t.Errorf("expected working tree to include %s, got %v", want, paths)
		}
	}
}

func TestNativeGitScanner_Staged(t *testing.T) {
	dir := testRepo(t)
	s := gitscanner.NewNative()

	ch, err := s.Scan(context.Background(), gitscanner.Repository{Path: dir, Mode: gitscanner.ModeStaged}, cerberus.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	artifacts := collect(t, ch)

	if len(artifacts) != 1 {
		t.Fatalf("expected exactly 1 staged artifact, got %d: %+v", len(artifacts), artifacts)
	}
	if artifacts[0].Path != "staged.env" {
		t.Errorf("expected staged.env, got %s", artifacts[0].Path)
	}
	if artifacts[0].SourceType != cerberus.SourceGitStaged {
		t.Errorf("unexpected SourceType %q", artifacts[0].SourceType)
	}
}

func TestNativeGitScanner_CommitAndBranch(t *testing.T) {
	dir := testRepo(t)
	s := gitscanner.NewNative()

	ch, err := s.Scan(context.Background(), gitscanner.Repository{Path: dir, Mode: gitscanner.ModeBranch, Ref: "main"}, cerberus.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan (branch): %v", err)
	}
	artifacts := collect(t, ch)

	for _, a := range artifacts {
		if a.Path == "secret.env" && string(a.Content) != "# secret removed\n" {
			t.Errorf("HEAD content for secret.env should reflect the second commit, got %q", a.Content)
		}
		if a.Commit == "" {
			t.Errorf("expected Commit to be set for branch-mode artifact %s", a.Path)
		}
	}
	// staged.env is index-only, not committed, so it must not appear.
	for _, a := range artifacts {
		if a.Path == "staged.env" {
			t.Errorf("staged.env is uncommitted and must not appear in branch-mode scan")
		}
	}
}

func TestNativeGitScanner_FullHistory_IncludesRootCommit(t *testing.T) {
	dir := testRepo(t)
	s := gitscanner.NewNative()

	ch, err := s.Scan(context.Background(), gitscanner.Repository{Path: dir, Mode: gitscanner.ModeFullHistory}, cerberus.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan (full-history): %v", err)
	}
	artifacts := collect(t, ch)

	foundOriginalSecret := false
	for _, a := range artifacts {
		if a.Path == "secret.env" && strings.Contains(string(a.Content), "AKIAAAAAAAAAAAAAAAA1") {
			foundOriginalSecret = true
		}
	}
	if !foundOriginalSecret {
		t.Fatal("expected full-history scan to surface the secret from the root commit, which was later removed from HEAD")
	}
}
