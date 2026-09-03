# Benchmark corpus

`testdata/corpus/` holds the true-positive and false-positive samples
used to calibrate scoring thresholds (see
[`../architecture/scoring.md`](../architecture/scoring.md)) and track
precision/recall over time.

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
