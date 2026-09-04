package prompt

import (
	"os"
	"strings"
	"testing"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func TestLoadDir_Valid(t *testing.T) {
	store, err := LoadDir(os.DirFS("testdata/valid"), ".")
	if err != nil {
		t.Fatalf("LoadDir: unexpected error: %v", err)
	}

	ids := store.IDs()
	if len(ids) != 1 || ids[0] != "greeting" {
		t.Fatalf("IDs() = %v, want [greeting]", ids)
	}

	latest, err := store.Get("greeting")
	if err != nil {
		t.Fatalf("Get(greeting): unexpected error: %v", err)
	}
	if latest.Version != 2 {
		t.Fatalf("Get(greeting).Version = %d, want 2 (the highest loaded version)", latest.Version)
	}

	v1, err := store.GetVersion("greeting", 1)
	if err != nil {
		t.Fatalf("GetVersion(greeting, 1): unexpected error: %v", err)
	}
	if v1.Version != 1 {
		t.Fatalf("GetVersion(greeting, 1).Version = %d, want 1", v1.Version)
	}

	if _, err := store.GetVersion("greeting", 99); err == nil {
		t.Fatalf("GetVersion(greeting, 99): expected error for unloaded version, got nil")
	}

	if _, err := store.Get("does-not-exist"); err == nil {
		t.Fatalf("Get(does-not-exist): expected error, got nil")
	}
}

func TestTemplate_VersionString(t *testing.T) {
	store, err := LoadDir(os.DirFS("testdata/valid"), ".")
	if err != nil {
		t.Fatalf("LoadDir: unexpected error: %v", err)
	}
	v1, err := store.GetVersion("greeting", 1)
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if got, want := v1.VersionString(), "greeting@1"; got != want {
		t.Fatalf("VersionString() = %q, want %q", got, want)
	}
}

func TestTemplate_Render(t *testing.T) {
	store, err := LoadDir(os.DirFS("testdata/valid"), ".")
	if err != nil {
		t.Fatalf("LoadDir: unexpected error: %v", err)
	}
	tmpl, err := store.GetVersion("greeting", 1)
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}

	input := cerberus.ValidationInput{
		RuleID:          "aws-access-key-id",
		Entropy:         4.2,
		Path:            "path/to/file.env",
		RedactedContext: "AWS_ACCESS_KEY_ID=[REDACTED]",
	}

	out, err := tmpl.Render(input)
	if err != nil {
		t.Fatalf("Render: unexpected error: %v", err)
	}

	for _, want := range []string{
		input.Path,
		input.RuleID,
		"4.2",
		input.RedactedContext,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Render() output %q does not contain %q", out, want)
		}
	}

	// The raw secret value must never be constructible from the input:
	// only the already-redacted context is threaded through.
	if strings.Contains(out, "AKIA") {
		t.Errorf("Render() output unexpectedly looks like it contains raw key material: %q", out)
	}
}

func TestTemplate_Render_ZeroValue(t *testing.T) {
	var zero Template
	if _, err := zero.Render(cerberus.ValidationInput{}); err == nil {
		t.Fatalf("Render on zero-value Template: expected error, got nil")
	}
}

func TestLoadDir_MissingDir(t *testing.T) {
	if _, err := LoadDir(os.DirFS("testdata"), "does-not-exist"); err == nil {
		t.Fatalf("LoadDir(missing dir): expected error, got nil")
	}
}

func TestLoadDir_MissingID(t *testing.T) {
	if _, err := LoadDir(os.DirFS("testdata/malformed_missing_id"), "."); err == nil {
		t.Fatalf("LoadDir: expected error for template missing \"id\", got nil")
	} else if !strings.Contains(err.Error(), "id") {
		t.Fatalf("LoadDir error = %v, want it to mention the missing \"id\" field", err)
	}
}

func TestLoadDir_MissingVersion(t *testing.T) {
	if _, err := LoadDir(os.DirFS("testdata/malformed_missing_version"), "."); err == nil {
		t.Fatalf("LoadDir: expected error for template missing \"version\", got nil")
	} else if !strings.Contains(err.Error(), "version") {
		t.Fatalf("LoadDir error = %v, want it to mention the missing \"version\" field", err)
	}
}

func TestLoadDir_NoFrontMatter(t *testing.T) {
	if _, err := LoadDir(os.DirFS("testdata/malformed_no_front_matter"), "."); err == nil {
		t.Fatalf("LoadDir: expected error for template with no front matter, got nil")
	}
}

func TestLoadDir_DuplicateIDVersion(t *testing.T) {
	if _, err := LoadDir(os.DirFS("testdata/malformed_duplicate"), "."); err == nil {
		t.Fatalf("LoadDir: expected error for duplicate (id, version) pair, got nil")
	} else if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("LoadDir error = %v, want it to mention \"duplicate\"", err)
	}
}

func TestLoadDir_MalformedTemplateBody(t *testing.T) {
	if _, err := LoadDir(os.DirFS("testdata/malformed_bad_template"), "."); err == nil {
		t.Fatalf("LoadDir: expected error for a body that fails to parse as a Go template, got nil")
	}
}

// TestChecksum_DetectsWordingChangeWithoutVersionBump demonstrates, in
// isolation (independent of the real prompts/ lock in
// prompt_lock_test.go), the mechanism that satisfies issue #16's
// acceptance criterion: a checksum recorded for a given (id, version)
// pair must fail to match once a template's wording changes but its
// version does not.
func TestChecksum_DetectsWordingChangeWithoutVersionBump(t *testing.T) {
	store, err := LoadDir(os.DirFS("testdata/valid"), ".")
	if err != nil {
		t.Fatalf("LoadDir: unexpected error: %v", err)
	}
	original, err := store.GetVersion("greeting", 1)
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	lockedChecksum := original.Checksum() // simulates a checksum pinned at release time

	// Someone edits the wording but forgets to bump "version: 1" in the
	// front matter.
	edited := original
	edited.Body = strings.Replace(edited.Body, "Hello", "Howdy", 1)

	if edited.Checksum() == lockedChecksum {
		t.Fatalf("expected checksum to change when body text changes at a fixed version")
	}
}

func TestChecksum_ChangesWithBody(t *testing.T) {
	store, err := LoadDir(os.DirFS("testdata/valid"), ".")
	if err != nil {
		t.Fatalf("LoadDir: unexpected error: %v", err)
	}
	v1, _ := store.GetVersion("greeting", 1)
	v2, _ := store.GetVersion("greeting", 2)

	if v1.Checksum() == v2.Checksum() {
		t.Fatalf("Checksum() for two templates with different bodies must differ")
	}
	if first, second := v1.Checksum(), v1.Checksum(); first != second {
		t.Fatalf("Checksum() must be deterministic: %q != %q", first, second)
	}
}
