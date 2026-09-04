// Package architecture holds architecture-fitness tests: assertions
// about the import graph itself, not runtime behavior. See
// docs/adr/0008-data-control-remediation-planes.md for the plane
// definitions this enforces.
package architecture

import (
	"encoding/json"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/HaK0exe/cerberus"

// dataPlanePrefixes are packages that run deterministic detection and
// scanning against untrusted, attacker-influenced input (scanned
// files, crawled web pages, Git history/blobs). Per ADR-0003, this
// code must never be able to reach privileged remediation execution or
// the control-surface MCP server, however indirectly.
var dataPlanePrefixes = []string{
	modulePath + "/internal/detector",
	modulePath + "/internal/rules",
	modulePath + "/internal/scanner",
	modulePath + "/internal/llm",
}

// remediationPlanePrefixes are the only packages allowed to hold
// privileged, credential-mutating executor code (ADR-0003).
var remediationPlanePrefixes = []string{
	modulePath + "/internal/remediation",
}

// controlPlanePrefixes documents the control plane's package list for
// ADR cross-reference and is used by
// TestSharedDomainContractImportsNoPlane below; the data/remediation
// boundary tests don't need it directly, since they check the other
// two planes' rules instead.
var controlPlanePrefixes = []string{
	modulePath + "/internal/findings",
	modulePath + "/internal/credentials",
	modulePath + "/internal/risk",
	modulePath + "/internal/intelligence",
	modulePath + "/internal/policyengine",
	modulePath + "/internal/policy",
	modulePath + "/internal/audit",
	modulePath + "/internal/mcp",
	modulePath + "/internal/queue",
	modulePath + "/internal/storage",
	modulePath + "/internal/config",
}

var mcpPlanePrefixes = []string{
	modulePath + "/internal/mcp",
}

// pkgInfo mirrors the subset of `go list -json` fields this test uses.
type pkgInfo struct {
	ImportPath string
	Deps       []string
}

func hasPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// loadPackages shells out to `go list -deps -json ./...` rather than
// importing golang.org/x/tools/go/packages, which is not a dependency
// of this module and this slice must not add — see ADR-0008.
func loadPackages(t *testing.T) []pkgInfo {
	t.Helper()

	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH; skipping architecture boundary test")
	}

	cmd := exec.Command("go", "list", "-deps", "-json", "./...")
	cmd.Dir = "../.." // repo root, relative to internal/architecture
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go list -deps -json ./... failed: %v\nstderr:\n%s", err, exitErr.Stderr)
		}
		t.Fatalf("go list -deps -json ./...: %v", err)
	}

	// `go list -json` with multiple packages emits a stream of
	// concatenated JSON objects, not a JSON array — decode with
	// json.Decoder in a loop.
	dec := json.NewDecoder(strings.NewReader(string(out)))
	var pkgs []pkgInfo
	for dec.More() {
		var p pkgInfo
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decoding go list output: %v", err)
		}
		// Only keep packages inside this module; Deps also lists
		// stdlib/third-party packages, which is exactly what we want
		// to search *through* below, but we only report on our own
		// packages as offenders.
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func byImportPath(pkgs []pkgInfo) map[string]pkgInfo {
	m := make(map[string]pkgInfo, len(pkgs))
	for _, p := range pkgs {
		m[p.ImportPath] = p
	}
	return m
}

// TestDataPlaneNeverImportsRemediationOrMCP enforces ADR-0003 and
// ADR-0008: a scanner/detector/LLM-validator package that is exposed
// to untrusted, attacker-influenced content (scanned files, crawled
// web pages, Git history) must never be able to transitively reach
// privileged remediation-execution code or the MCP control surface. If
// it could, a bug or injection in detection would become a path to
// credential-revoking APIs or agent-facing tools.
func TestDataPlaneNeverImportsRemediationOrMCP(t *testing.T) {
	pkgs := loadPackages(t)
	if len(pkgs) == 0 {
		t.Fatal("go list returned no packages — is this test running inside the module?")
	}

	var violations []string
	for _, p := range pkgs {
		if !hasPrefix(p.ImportPath, dataPlanePrefixes) {
			continue
		}
		for _, dep := range p.Deps {
			if hasPrefix(dep, remediationPlanePrefixes) {
				violations = append(violations, p.ImportPath+" (data plane) imports "+dep+" (remediation plane, forbidden)")
			}
			if hasPrefix(dep, mcpPlanePrefixes) {
				violations = append(violations, p.ImportPath+" (data plane) imports "+dep+" (MCP control surface, forbidden)")
			}
		}
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("data-plane boundary violated (see docs/adr/0008-data-control-remediation-planes.md):\n  %s",
			strings.Join(violations, "\n  "))
	}
}

// TestRemediationPlaneDoesNotShortcutIntoRawScanning enforces that
// remediation acts on control-plane state (Credential, Incident,
// RemediationPlan) rather than re-scanning or re-detecting secrets
// itself as a privileged shortcut. Today internal/remediation is a
// types-only stub with no such imports, so this passes trivially; it
// exists to catch a regression once Phase K adds executor code.
func TestRemediationPlaneDoesNotShortcutIntoRawScanning(t *testing.T) {
	pkgs := loadPackages(t)
	byPath := byImportPath(pkgs)

	forbidden := []string{
		modulePath + "/internal/detector",
		modulePath + "/internal/scanner",
	}

	var violations []string
	for path, p := range byPath {
		if !hasPrefix(path, remediationPlanePrefixes) {
			continue
		}
		for _, dep := range p.Deps {
			if hasPrefix(dep, forbidden) {
				violations = append(violations, path+" (remediation plane) imports "+dep+" (data plane, forbidden — act on Credential/Incident/Plan instead)")
			}
		}
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("remediation-plane boundary violated (see docs/adr/0008-data-control-remediation-planes.md):\n  %s",
			strings.Join(violations, "\n  "))
	}
}

// TestSharedDomainContractImportsNoPlane enforces that pkg/cerberus —
// the stable contract every plane depends on — never depends back on
// any of them. A cycle here would mean the "shared contract" is
// secretly coupled to one plane's implementation details.
func TestSharedDomainContractImportsNoPlane(t *testing.T) {
	pkgs := loadPackages(t)
	byPath := byImportPath(pkgs)

	p, ok := byPath[modulePath+"/pkg/cerberus"]
	if !ok {
		t.Fatal("pkg/cerberus not found in `go list -deps -json ./...` output")
	}

	forbidden := append(append(append([]string{}, dataPlanePrefixes...), controlPlanePrefixes...), remediationPlanePrefixes...)

	var violations []string
	for _, dep := range p.Deps {
		if hasPrefix(dep, forbidden) {
			violations = append(violations, "pkg/cerberus imports "+dep)
		}
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("pkg/cerberus must import no plane-specific package (see docs/adr/0008-data-control-remediation-planes.md):\n  %s",
			strings.Join(violations, "\n  "))
	}
}
