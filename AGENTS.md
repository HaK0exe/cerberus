# AGENTS.md — Cerberus

Single Go module (`github.com/HaK0exe/cerberus`, Go 1.25+). Binaries in `cmd/` (`cerberus` CLI + `cerberus-api/worker/mcp` stubs); public contract in `pkg/cerberus`; implementations in `internal/`.

## Verify (CI gate — all must pass)

```bash
go build ./...
go vet ./...
gofmt -l .              # must print nothing
go test -race ./...
staticcheck ./...       # CI installs honnef.co/go/tools/cmd/staticcheck@latest
gosec -quiet ./...
govulncheck ./...
```

`make lint` = `vet` + `fmt` only; run the rest explicitly. Focused checks:
`go test ./internal/detector/...`, `go run ./cmd/cerberus rules test <rule-id> "<sample>"`.

## Architecture boundaries (enforced in review)

- `pkg/cerberus` is the stable contract (Artifact, Finding, Rule, Detector, Validator…). Never import AWS/HTTP/MCP there; keep it provider/transport agnostic.
- `internal/*` packages depend only on `pkg/cerberus` + narrow contracts — never on another `internal/*` package's internals or on provider SDK types (Gitleaks, AWS SDK, colly…). Adapt those at the owning package boundary.
- CLI-only shortcuts exist: `cmd/cerberus` uses an ephemeral fingerprint key and in-memory stores. Fingerprints are NOT stable across invocations (see `buildDetector` TODO) — don't build dedup/correlation on CLI output.

## Security invariants (never violate; security-touching PRs need 2 reviewers + ADR/threat-model update)

- **No raw secret persists.** `Finding` carries HMAC fingerprint + masked prefix + location/score only. Never log/print/store the value; `--unmask` is local-triage-only, never in CI/logs.
- **LLM is never sovereign.** Opt-in via `--llm` + `--offline=false` only; it sees sanitized input, gets no tools/network, and can only nudge `llm_review`-band scores — never delete findings or trigger remediation.
- **Detection ≠ remediation.** Scanner has zero mutating permissions; remediation defaults to dry-run + human approval.
- **Web scanner:** DNS+IP validation before AND after every redirect; block RFC1918/loopback/link-local/`169.254.169.254`. Respect `robots.txt` by default. Report vulns privately via GitHub Security Advisories, never a public issue.

## Detection rules + corpus

- Rules: YAML in `rules/**/*.yaml` (`cloud/ generic/ payment/ private-keys/ scm/`), loaded by `internal/rules.LoadDir`. RE2 regex, `secret_group` = capture group holding the secret. Don't create a new top-level dir without an issue. Keep provider logic in YAML, not Go.
- Scoring (`internal/detector/scoring.go`, ±200B context window): base `confidence` +0.10 entropy-ok / −0.15 entropy-bad (if enabled) / +0.10 keyword / −0.40 negative keyword. Bands: `<0.50` ignore, `[0.50,0.70)` low-confidence (debug via `WithMinEmitBand`), `[0.70,0.90)` llm_review, `≥0.90` finding. Thresholds are calibrated, not constants — changing rules/scoring requires corpus validation.
- New/changed rule PR must add: true-positive sample in `testdata/corpus/true_positive/` (+ `git/`/`web/` scanner-output fixtures where relevant, walked recursively) and a realistic false-positive in `false_positive/` if noise-prone. **Never commit a real secret, even revoked** — synthesize format-valid fakes. One secret per file, intent-named (e.g. `aws-access-key-id_fp_documentation.md`).

## Workflow

- `main` always releasable; branches `feature/<slug>`, `fix/<slug>`; rebase on `main` before PR. Open/claim an issue first for non-trivial work. Keep PRs to one concern.
- PR checklist: tests for new behavior (core `detector`/`rules`/`policy`/SSRF guard target >90%), `CHANGELOG.md` for user-visible changes, `gofmt` clean. Comment only non-obvious *why*, never *what*.
- Key docs over README prose: `docs/architecture/{overview,scoring}.md`, `docs/security/threat-model.md`, `docs/development/{writing-rules,corpus}.md`, `docs/adr/0001..0003`.
