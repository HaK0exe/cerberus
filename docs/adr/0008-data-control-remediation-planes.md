# ADR 0008: Data plane / control plane / remediation plane boundary

Status: Accepted
Date: 2026-09-04

## Context

ADR-0003 already establishes that detection and remediation must be
architecturally separate: a scanner exposed to untrusted,
attacker-influenced content (files, crawled pages, Git history) must
never hold or reach credential-revoking privileges. The broader
roadmap generalizes this into three planes — data plane (detection/
scanning), control plane (findings, correlation, risk, policy,
orchestration), and remediation plane (privileged execution) — and
asks for the separation to be made explicit in the code, with an
architecture test where practical.

At the point this ADR was written, `internal/*` is a flat, already-
working layout with several packages recently landed in parallel
(`internal/credentials`, `internal/risk`, `internal/intelligence`,
`internal/policyengine`) and at least one other concurrent session
actively editing `internal/scanner/web/**`. A physical directory move
— `internal/detector` → `internal/dataplane/detector`, etc. — would
touch every import in the repo, collide with in-flight work with no
coordination mechanism, and buys nothing functional: Go's compiler
already treats import paths, not directory nesting, as the real
boundary. There is no plugin-loading or build-tag mechanism today that
would benefit from physical separation.

## Decision

Define the three planes **logically**, by import-path prefix, and
enforce the boundary with a `go test`-driven architecture-fitness test
(`internal/architecture/boundary_test.go`) rather than moving files.

- **Data plane** — deterministic detection/scanning against untrusted
  input; must hold no privileged credentials, must never import the
  remediation plane or the MCP control surface:
  `internal/detector`, `internal/rules`, `internal/scanner/...` (all
  subpackages: `git`, `web`, `web/ssrf`, `web/frontier`),
  `internal/llm` (and future `internal/llm/ollama`,
  `internal/llm/llamacpp`).
- **Control plane** — reads findings, correlates, scores, decides;
  never itself executes a privileged action:
  `internal/findings`, `internal/credentials`, `internal/risk`,
  `internal/intelligence` (+ adapters), `internal/policyengine`,
  `internal/policy` (fingerprinting/masking), `internal/audit`,
  `internal/mcp`, `internal/queue`, `internal/storage`,
  `internal/config`.
- **Remediation plane** — the only place allowed to hold
  credential-mutating executor code: `internal/remediation` and
  everything under it (e.g. `internal/remediation/aws`).
- **Shared contract**: `pkg/cerberus` — every plane may depend on it;
  it must depend on none of them (a dependency back would mean the
  "stable contract" is secretly coupled to one plane's internals).

The test shells out to `go list -deps -json ./...` (stdlib
`os/exec` + `encoding/json`) rather than importing
`golang.org/x/tools/go/packages`, which is not currently a dependency
of this module — this slice adds zero new dependencies. It asserts
three things:

1. No data-plane package transitively imports anything under
   `internal/remediation` or `internal/mcp`.
2. No `internal/remediation` package imports `internal/detector` or
   `internal/scanner/...` directly — remediation must act on
   `Credential`/`Incident`/`Plan` from the control plane, not
   re-scan/re-detect as a privileged shortcut. (`internal/remediation`
   is currently types-only, so this passes trivially today; it exists
   to catch a regression once a future phase adds executor code.)
3. `pkg/cerberus` imports no plane-specific package at all.

Each failure names the offending package and the exact forbidden
import it pulled in, so a future violation is immediately explainable,
not just a red CI check.

## Consequences

- The boundary is enforced continuously (`go test ./...`) without a
  single file having moved, so this lands with zero risk of colliding
  with concurrent work elsewhere in the tree and zero risk of breaking
  any existing import.
- New packages must be added to the right list in
  `boundary_test.go` as they're introduced (e.g. once
  `internal/llm/ollama` lands) — this is a small, visible manual step,
  not automatic; a package added to the wrong plane or omitted
  entirely won't be checked until someone updates the list. Documented
  here rather than solved, since automatically inferring "which plane"
  a new package belongs to isn't well-defined without human judgment.
- Physical restructuring into `internal/dataplane/` /
  `internal/controlplane/` / `internal/remediation/` directories
  remains available as a later, low-risk migration — worth doing once
  there's a concrete forcing function (e.g. a community-plugin
  mechanism that needs `.so`-style loading or separate build
  constraints per plane) rather than for its own sake on a single
  static binary, where the directory layout has no runtime effect.

## Alternatives considered

- **Physical directory move now** — rejected: high blast radius across
  every import in the repo, real collision risk with a concurrently
  edited `internal/scanner/web/**`, and no functional benefit for a
  single Go binary where import paths are already the enforced
  boundary; the compiler does not care about directory nesting.
- **A dependency-linter config (e.g. `depguard`) instead of a Go
  test** — rejected for now: `depguard` would be a new dependency,
  which this slice deliberately avoids, and it typically runs only in
  CI/lint tooling rather than under plain `go test ./...`, where every
  contributor and every existing CI step already looks for failures.
  A `go test` using only `go list` output keeps the check inside the
  same signal contributors already watch, at the cost of shelling out
  to the `go` binary from within a test (acceptable: `go` is always on
  PATH in this project's build/test/CI environments).
