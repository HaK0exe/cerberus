# Writing a detection rule

Rules are plain YAML lists loaded from `rules/**/*.yaml` by
`internal/rules.LoadDir` — no code required for a new pattern-based
rule.

## Schema

```yaml
- id: aws-access-key-id        # required, unique, kebab-case
  name: AWS Access Key ID      # required, human-readable

  regex: '\b((?:AKIA|ASIA)[A-Z0-9]{16})\b'  # required, RE2 syntax (Go regexp)
  secret_group: 1               # capture group holding the secret value (0 = whole match)

  keywords: [aws, access_key]           # optional; proximity match adds +0.10 to score
  negative_keywords: [example, placeholder]  # optional; proximity match subtracts 0.40

  entropy:
    enabled: false               # if true, Shannon entropy of the matched value is checked
    threshold: 4.2                # bits/byte; only meaningful when enabled: true

  severity: high                 # low | medium | high | critical
  confidence: 0.98                # base score in [0, 1] before context adjustments
```

See [`../architecture/scoring.md`](../architecture/scoring.md) for how
`confidence`, `entropy`, `keywords`, and `negative_keywords` combine
into a final score, and the classification bands that determine
whether a match becomes a `Finding`.

## Where to put a new rule

```text
rules/cloud/          AWS, Azure, GCP credentials
rules/scm/             GitHub, GitLab tokens
rules/payment/         Stripe and other payment provider keys
rules/generic/         provider-agnostic patterns (JWTs, generic API keys, passwords)
rules/private-keys/    PEM/SSH private key material
```

Add a new file per provider family, or extend an existing one — don't
create a new top-level directory without discussion (open an issue
first).

## Testing a rule

```bash
go run ./cmd/cerberus rules test <rule-id> "<sample text>"
```

Before opening a PR for a new rule:

1. Add at least one true-positive sample to
   `testdata/corpus/true-positives/`.
2. If the pattern is prone to noise (generic keywords, moderate
   entropy), add at least one realistic false-positive sample to
   `testdata/corpus/false-positives/` (e.g. a UUID, a test fixture, a
   documentation example) and confirm it scores below
   `ThresholdFinding`.
3. Run `go test ./internal/detector/...` to confirm nothing regresses.

## Anti-patterns

- Don't set `confidence` near 1.0 for a generic, low-specificity regex
  — let context/entropy do the work, and expect it to land in the
  `llm_review` band rather than auto-finding.
- Don't add `negative_keywords` so broad they suppress real secrets
  (e.g. don't add `"key"` as a negative keyword for a key-detection
  rule).
- Don't hardcode logic in Go for something a YAML rule can express —
  keep `internal/detector` provider-agnostic.
