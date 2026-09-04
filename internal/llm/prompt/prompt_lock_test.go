package prompt

import (
	"fmt"
	"os"
	"testing"
)

// lockedChecksums pins the SHA-256 checksum (Template.Checksum) of every
// (id, version) pair that currently exists under the repo's real
// prompts/ directory.
//
// This is the enforcement mechanism for issue #16's acceptance
// criterion "changing a prompt's wording bumps its version": if a
// template's body changes, its checksum changes, but its key here
// ("id@version") stays the same — so TestPromptLock_ContentMatchesLockedVersion
// fails until the developer either reverts the wording or bumps the
// template's version (front matter "version:") and adds a new entry
// here for the new version.
//
// To regenerate after an intentional version bump, run:
//
//	GEN_PROMPT_LOCK=1 go test ./internal/llm/prompt/... -run TestPrintRealChecksums -v
//
// and copy the printed lines in here.
var lockedChecksums = map[string]string{
	"candidate_validation@1": "c9b3cf4d33bd043e17f7683f77c4d22a6ddc65a6ebd57c5e2e1d5fe169558192",
}

func TestPromptLock_ContentMatchesLockedVersion(t *testing.T) {
	store, err := LoadDir(os.DirFS("../../../prompts"), ".")
	if err != nil {
		t.Fatalf("LoadDir(prompts/): %v", err)
	}

	seen := make(map[string]bool)

	for _, id := range store.IDs() {
		tmpl, err := store.Get(id)
		if err != nil {
			t.Fatalf("Get(%q): %v", id, err)
		}
		key := tmpl.VersionString()
		seen[key] = true

		want, ok := lockedChecksums[key]
		if !ok {
			t.Errorf(
				"template %s has no entry in lockedChecksums (prompt_lock_test.go). "+
					"If this is a new template or an intentional version bump, add its checksum "+
					"(%s) to lockedChecksums. Regenerate with: GEN_PROMPT_LOCK=1 go test ./internal/llm/prompt/... -run TestPrintRealChecksums -v",
				key, tmpl.Checksum(),
			)
			continue
		}
		if got := tmpl.Checksum(); got != want {
			t.Errorf(
				"template %s wording changed (checksum %s, locked checksum %s) without a version bump. "+
					"Bump \"version\" in %s and add a new lockedChecksums entry for the new version — "+
					"do not just update this checksum in place.",
				key, got, want, tmpl.Path,
			)
		}
	}

	for key := range lockedChecksums {
		if !seen[key] {
			t.Errorf("lockedChecksums has stale entry %q with no matching template under prompts/", key)
		}
	}
}

// TestPrintRealChecksums is a throwaway helper to print the checksum of
// every template under the repo's real prompts/ directory, used to
// (re)seed lockedChecksums above. Skipped unless GEN_PROMPT_LOCK=1 is
// set; it makes no assertions of its own.
func TestPrintRealChecksums(t *testing.T) {
	if os.Getenv("GEN_PROMPT_LOCK") == "" {
		t.Skip("set GEN_PROMPT_LOCK=1 to print checksums")
	}
	store, err := LoadDir(os.DirFS("../../../prompts"), ".")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	for _, id := range store.IDs() {
		tmpl, _ := store.Get(id)
		fmt.Printf("%q: %q,\n", tmpl.VersionString(), tmpl.Checksum())
	}
}
