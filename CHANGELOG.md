# Changelog

All notable changes to this project are documented here. Format based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Repository scaffold: module layout (`cmd/`, `pkg/cerberus`,
  `internal/*`), governance and community files, CI skeleton.
- Domain model: `Artifact`, `Candidate`, `Finding`, `Rule`, and the
  `Detector`/`Validator`/`JobQueue` contracts in `pkg/cerberus`.
- Deterministic detection engine: rule loader, regex matching, Shannon
  entropy filter, keyword-based context scoring, HMAC-SHA256
  fingerprinting, masked-prefix rendering.
- Initial rule set: AWS keys, GitHub tokens, Stripe keys, generic
  JWT/API-key/password patterns, PEM private keys.
- CLI (`cerberus`): `scan file`, `rules list`, `rules test`; stubs for
  `git scan`, `web scan`, `findings`, `remediation`, `server`, `mcp`.
- Unit tests for the detection engine.
- `cerberus git scan`: functional NativeGitScanner (working tree,
  staged, commit, branch, full history) shelling out to `git`, wired
  into the CLI and detection pipeline (#1, #2, #4).
- `--format sarif` for `scan file` and `git scan`, producing valid
  SARIF 2.1.0 output with no raw secret values (#4).
