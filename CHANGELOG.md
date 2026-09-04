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
- `cerberus web scan`: colly-based web crawler wired into the CLI and
  detection pipeline, replacing the `internal/scanner/web` stub (#6).
- `internal/scanner/web/ssrf`: mandatory SSRF guard — DNS resolution
  and IP validation before every request, re-validated on every
  redirect hop via dial-time IP pinning, blocking RFC1918/loopback/
  link-local ranges and `169.254.169.254` (never allow-listable) per
  `docs/security/ssrf.md` (#5).
- `robots.txt` handling: respected by default, fail-open on fetch
  failure, `--ignore-robots` opt-in with the required warning (#7).
- Crawl scope enforcement (`--allowed-domains`, `--exclude-path`)
  checked on every discovered link and on every redirect hop, not
  just the start URL (#8).
- JavaScript extraction: inline `<script>` content, linked
  `.js`/`.mjs`/`.cjs` files, and `sourceMappingURL`-referenced source
  maps, downloaded through the SSRF-guarded client with a hard size
  cap; disabled entirely by `--javascript=false` (#9).
- `internal/scanner/web/frontier`: distributed crawl frontier —
  `scan_id`/`url`/`depth` message format over `cerberus.JobQueue`,
  URL canonicalization (scheme/host case, default ports, trailing
  slash, query-parameter order), and a `SHA256(canonical URL)` dedup
  layer so multiple workers sharing a queue never re-fetch the same
  page. Backed by `internal/queue.MemQueue` for now; the interface is
  the drop-in point for an SQS-backed queue once that lands (#11).
- Dedicated web-scanner security test suite covering every case in
  `docs/security/ssrf.md`'s required-tests list end-to-end through the
  crawler: direct SSRF, redirect-chain SSRF, DNS rebinding, the
  metadata endpoint, oversized/decompression-bomb-style bodies, and
  both redirect-loop and unbounded-page-graph crawl termination (#12).
- `internal/queue/sqs`: `cerberus.JobQueue` implementation against AWS
  SQS (or any SQS-compatible endpoint, e.g. ElasticMQ), with a 256KiB
  message-size limit enforced (and documented) in `Publish`, and a
  `Consume` long-poll loop that exits cleanly — channel closed, no
  goroutine left running — as soon as its context is done. No AWS
  credentials or client construction inside `pkg/cerberus`; callers
  supply their own `*sqs.Client`. Round-trip and cancellation behavior
  is covered both by fake-API unit tests and by an integration test
  against a real, locally-started ElasticMQ container (skipped, not
  failed, when Docker isn't available) (#10).
- `internal/llm/cache`: HMAC-keyed `llm.Cache` implementation —
  `KeyDeriver` derives a non-guessable, non-reversible cache key from
  every `CacheKeyInput` field (candidate fingerprint, context hash,
  model ID, prompt version, rules version) via a server-side HMAC key,
  never a bare hash, mirroring `internal/policy.Fingerprinter`; `MemCache`
  is an in-memory, TTL-enforcing, concurrency-safe implementation for
  local/CLI use. The plain `llm.Cache` interface is the drop-in point
  for a future DynamoDB-backed (`cerberus-cache` table) implementation,
  Sprint 4 (#19).
- `internal/llm.Sanitize`: real context-sanitizer implementation
  replacing the Sprint 0 no-op placeholder — redacts the raw candidate
  secret value with a fixed-width placeholder (no length/position
  leak) and neutralizes prompt-injection-shaped text (instruction
  overrides, role-play jailbreaks, chat control-token smuggling,
  fabricated `ValidationResult`-shaped JSON) before context ever
  reaches a Validator, per ADR-0002 (#17).
- `internal/llm.ParseValidationResult`: strict JSON schema validation
  for `cerberus.ValidationResult` (`classification`/`confidence`/
  `reason`, no unknown fields, no trailing data, closed
  `ValidationClassification` enum, confidence clamped to `[0, 1]`),
  plus `ParseValidationResultWithRetry`, which retries a Validator
  call a bounded number of times and degrades to a safe "uncertain"
  result instead of ever propagating malformed model output into the
  pipeline (#18).
- `internal/llm/prompt`: versioned LLM prompt template loader — Markdown
  templates under `prompts/` with an `id`/`version` front matter block,
  `Store.Get`/`GetVersion` for latest-or-pinned lookups, and
  `Template.Render` against `cerberus.ValidationInput`. A checksum-lock
  test (`prompt_lock_test.go`) fails the build if a template's wording
  changes without a matching version bump, so `PromptVersion` stays a
  reliable cache-key input for `llm.CacheKeyInput` (#16).
- `internal/llm/circuitbreaker`: `cerberus.Validator` decorator adding
  a per-call timeout and a closed/open/half-open circuit breaker
  around any underlying Validator (Ollama, llama.cpp, ...). After a
  configurable number of consecutive failures or timeouts the breaker
  opens and short-circuits further calls; a breaker-open or timed-out
  call returns a wrapped `ErrFallback` sentinel (`IsFallback`) instead
  of a blocking error, so callers can fall back to the pre-LLM
  deterministic score. State transitions are logged and exposed via
  `Breaker.State()`/`Breaker.Stats()` for operators (#20).
- `internal/llm/llamacpp`: second `cerberus.Validator` implementation,
  against a llama.cpp server's OpenAI-compatible `/v1/chat/completions`
  HTTP endpoint, selectable as a fallback when Ollama is unavailable.
  Renders prompts via `internal/llm/prompt`, parses responses through
  `internal/llm.ParseValidationResultWithRetry` (no bespoke JSON
  parsing), and depends on an injectable `HTTPClient` interface so
  unit tests run against an `httptest` fake server (success, HTTP
  errors, malformed/retried JSON, context cancellation) with no real
  llama.cpp server required. Base URL and model are required
  `Config` fields, never hardcoded (#15).

### Deviations from the original issue scope

- S2-11 was scoped as an "SQS frontier"; SQS support itself is S2-10,
  which has not landed yet. `internal/scanner/web/frontier` implements
  the full message schema, canonicalization, and dedup semantics S2-11
  requires against `cerberus.JobQueue`/`internal/queue.MemQueue`
  instead, so it drops in against a real SQS-backed `JobQueue` with no
  interface changes once S2-10 exists. The single-process
  `cerberus web scan` CLI path does not (yet) drive multiple worker
  processes off this frontier — that requires a `cerberus web worker`
  command, deliberately left for when S2-10 lands. See the comment on
  issue #11 for the same note.
