# Contributing to Cerberus

Thank you for considering a contribution. Cerberus handles secret
detection and remediation, so we hold code quality and security review
to a higher bar than a typical project — please read this document
before opening a PR.

## Before you start

- For anything non-trivial, open an issue first (or claim an existing
  one) so we can align on approach before you invest time.
- Security-sensitive changes (detection bypass, SSRF handling,
  remediation, MCP authorization, credential handling) should mention
  the relevant [ADR](docs/adr) or propose a new one.

## Development setup

Requires Go 1.25+.

```bash
git clone https://github.com/HaK0exe/cerberus.git
cd cerberus
go build ./...
go test ./...
```

Useful commands:

```bash
go vet ./...
gofmt -l .              # should print nothing
go run ./cmd/cerberus scan file testdata/corpus/true-positives/*
```

## Branching model

- `main` is always releasable.
- Short-lived branches: `feature/<slug>`, `fix/<slug>`.
- No long-lived `develop` branch.
- Rebase on `main` before opening a PR; keep history readable.

## Pull requests

- One reviewer minimum; **two reviewers** for anything touching
  security-critical paths (detector scoring, SSRF guard, MCP
  authorization, remediation, IAM/Terraform).
- CI must be green: `go build`, `go test -race`, `go vet`,
  `staticcheck`, `gosec`, `govulncheck`.
- Include tests for new behavior. Core packages
  (`internal/detector`, `internal/rules`, `internal/policy`,
  `internal/scanner/web` SSRF guard once implemented) target >90%
  coverage.
- Update `CHANGELOG.md` for user-visible changes.
- Keep PRs scoped to one concern — small PRs review faster and revert
  more safely.

## Code style

- Run `gofmt` before committing (CI enforces this).
- No comments explaining *what* code does — name things clearly
  instead. Comment only non-obvious *why* (a constraint, a workaround,
  an invariant a reader could otherwise violate).
- `pkg/cerberus` is the stable public contract: changes there need
  extra scrutiny and should stay provider/transport agnostic (no AWS,
  HTTP, or MCP types).
- Provider-specific types (Gitleaks, AWS SDK, colly, ...) must be
  adapted at the boundary of their `internal/*` package — never leak
  into `pkg/cerberus` or across unrelated internal packages.

## Writing a detection rule

See [`docs/development/writing-rules.md`](docs/development/writing-rules.md).
New rules should ship with:

- at least one true-positive sample in `testdata/corpus/true-positives/`
- at least one realistic false-positive sample in
  `testdata/corpus/false-positives/` if the rule is prone to noise

## Reporting security issues

Do **not** open a public issue for a vulnerability. See
[`SECURITY.md`](SECURITY.md).

## Versioning

Cerberus follows [Semantic Versioning](https://semver.org/). The
ruleset, prompt templates, MCP schema, and database schema are
versioned independently — see [`ROADMAP.md`](ROADMAP.md) §Versioning.
