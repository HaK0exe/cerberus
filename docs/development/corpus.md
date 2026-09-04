# Benchmark corpus

`testdata/corpus/` holds the true-positive and false-positive samples
used to calibrate scoring thresholds (see
[`../architecture/scoring.md`](../architecture/scoring.md)) and track
precision/recall over time.

## Current size

As of the git-history and web/JS fixture expansion (issue #13):

```text
true_positive/   72 samples total
  (root)         12 samples -- general rule-family fixtures
  git/           30 samples -- git diffs/patches, commit messages,
                                and historical blobs (as `git show
                                <sha>:<path>` would surface them)
  web/           30 samples -- minified JS, source maps, HTML with
                                inline <script>, .mjs/.cjs modules

false_positive/ 130 samples total
  (root)         10 samples -- general rule-family fixtures
  git/           60 samples -- packed-refs/reflog metadata, commit
                                messages without values, placeholder
                                diffs, historical docs
  web/           60 samples -- env-var lookups, JSDoc examples, clean
                                source maps, analytics placeholders,
                                minified chunk hashes/UUIDs
```

Samples under `true_positive/git/` and `false_positive/git/` are
tagged `git-` (in a rule-neutral id, e.g. `git-metadata_fp_...`) or
carry a `git-*` description segment (e.g.
`generic-api-key-assignment_git-diff-added-line-1.diff`) to mark them
as representative of `internal/scanner/git`'s output (diff/patch
content, commit messages, and full-file blobs at a historical commit).
Samples under `true_positive/web/` and `false_positive/web/` are
tagged the same way with a `web-` segment, representative of
`internal/scanner/web`'s output (inline `<script>` bodies, linked
`.js`/`.mjs`/`.cjs` files, and `sourceMappingURL`-referenced source
maps).

## Target size

- 5,000 synthetic true positives across all rule families
- 10,000 realistic false positives, including: UUIDs, SHA hashes,
  checksums, random IDs, test fixtures, documentation examples, JWT
  examples, API examples, minified JS, Terraform plans, CloudFormation
  templates, Dockerfiles, npm bundles, GitHub Actions workflows

## Rules

- **Never commit a real secret**, even an expired/revoked one. All
  true-positive samples must be synthetically generated to match a
  rule's pattern (e.g. a syntactically valid but never-issued AWS
  key format).
- Keep samples small and focused — one secret (or one clearly-labeled
  absence of one) per file, named to indicate intent, e.g.
  `aws-access-key-id_basic.env`,
  `aws-access-key-id_fp_documentation.md`.
- When adding a rule (see
  [`writing-rules.md`](writing-rules.md)), add corpus samples in the
  same PR.
- Samples may live directly under `true_positive/`/`false_positive/`
  (rule-family fixtures) or in a nested source-type subdirectory such
  as `git/` or `web/` (fixtures representative of a specific scanner's
  output) — `internal/detector/benchmark.LoadCorpus` walks both label
  directories recursively, so nested subdirectories are picked up the
  same as flat files.

## Metrics tracked

```text
precision
recall
F1
false positives / 1,000 files
secrets / GB
files / second, MB / second
LLM calls / candidate, LLM latency (once Sprint 3 lands)
```

A benchmark harness (`go test ./testdata/... -run Corpus`, or a
dedicated `cerberus rules bench` command) is tracked as a Sprint 1/2
follow-up issue — not yet implemented.
