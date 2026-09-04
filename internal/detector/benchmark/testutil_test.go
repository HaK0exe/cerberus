package benchmark

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// realCorpusFS returns an fs.FS rooted at the repository root, derived
// from this test file's own path rather than the process's working
// directory — `go test` runs with cwd set to the package directory,
// so relying on cwd would break depending on how the test is invoked.
func realCorpusFS(t *testing.T) fs.FS {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/detector/benchmark/testutil_test.go -> repo root is
	// three directories up.
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	return os.DirFS(root)
}
