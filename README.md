# Cerberus

**Cerberus** is an open-source platform for detecting, qualifying, and
safely remediating exposed secrets — across Git repositories and
history, websites, JavaScript bundles, text artifacts, and CI/CD
pipelines.

> **Status: pre-alpha / active scaffolding.** The detection engine
> (`cerberus scan file`) works end-to-end. Git/web scanning, LLM
> validation, the cloud control plane, MCP server, and AWS remediation
> are being built sprint by sprint — see [Roadmap](#roadmap) and the
> [issue tracker](../../issues).

```bash
$ cerberus scan file .env
[high] aws-access-key-id  AKIA****************  confidence=0.98  .env
```

## Why Cerberus

Most secret scanners stop at "regex matched → alert". Cerberus treats
detection, qualification, and remediation as three **separate,
independently-privileged** concerns:

- **Detection** is deterministic and cheap: rules + entropy + context
  scoring, no network calls, no LLM required.
- **Qualification** is optional and local: an on-box LLM (Ollama /
  llama.cpp) can nudge an ambiguous score up or down and explain a
  finding — it is never authoritative and never sees a raw secret.
- **Remediation** is a distinct pipeline with its own IAM role,
  mandatory dry-run default, and human approval gate. The component
  that *finds* a secret can never *revoke* it.

See [`docs/architecture/`](docs/architecture) for the full design and
[`docs/security/`](docs/security) for the threat model.

## Core principles

1. **No raw secret persists, ever, by default.** Findings store a
   type, provider, HMAC fingerprint, masked prefix, length, source
   location, score, and timestamp — never the secret value itself, in
   logs, traces, metrics, storage, or API/MCP responses.
2. **Detection and remediation are architecturally separate.** The
   scanner has zero IAM/GitHub/Vault-mutating permissions. See
   `Scanner → Detector → Finding Store → Remediation Planner →
   Approval → Remediation Worker`.
3. **The LLM is never sovereign.** It can raise/lower a score, classify
   context, or explain a finding — never delete a critical finding,
   trigger a revocation, hold cloud credentials, or reach the network
   on its own.

## Quick start

Requires Go 1.25+.

```bash
git clone https://github.com/HaK0exe/cerberus.git
cd cerberus
go build -o bin/cerberus ./cmd/cerberus

./bin/cerberus rules list
./bin/cerberus scan file path/to/file.env
./bin/cerberus scan file path/to/file.env --format json
```

Everything below is on the roadmap, not yet available:

```bash
cerberus git scan . --history          # Sprint 2
cerberus web scan https://example.com  # Sprint 2
cerberus server                        # Sprint 4
cerberus mcp                           # Sprint 4
cerberus remediation apply <id>        # Sprint 5
```

## Repository layout

```text
cmd/                 binaries: cerberus (CLI), cerberus-api, cerberus-worker, cerberus-mcp
pkg/cerberus/         stable public domain types & interfaces (Artifact, Finding, Rule, Detector, Validator...)
internal/detector/    regex + entropy + context scoring engine
internal/rules/       rule loader/compiler
internal/scanner/     git + web scanners (contracts now, implementations in Sprint 2)
internal/llm/         local LLM validator contracts (Ollama/llama.cpp — Sprint 3)
internal/remediation/ remediation plan/approval/execution contracts (AWS — Sprint 5)
internal/mcp/         MCP server (Sprint 4)
internal/policy/      fingerprinting, masking, secret-lifecycle helpers
internal/audit/       append-only audit trail
rules/                declarative YAML detection rules, organized by provider family
prompts/              versioned LLM validation prompt templates
testdata/corpus/      true/false positive corpus for precision/recall benchmarking
deploy/               Dockerfiles and Terraform for cloud deployment
docs/                 architecture, security, deployment, MCP, and development docs
```

See [`docs/architecture/overview.md`](docs/architecture/overview.md)
for how these pieces fit together.

## Detection pipeline

```text
Artifact → Preprocessor → Regex rules → Entropy filter → Context analysis
   → Allowlist/suppression → Deterministic scoring
        ├─ score ≥ 0.90            → Finding
        ├─ score < 0.50            → Ignore
        └─ 0.50 ≤ score < 0.90     → optional local-LLM review → Finding
```

Scoring bands are starting points, calibrated against
[`testdata/corpus`](testdata/corpus) — not fixed constants. See
[`docs/architecture/scoring.md`](docs/architecture/scoring.md).

## Writing a rule

Rules are plain YAML — no code required. See
[`rules/cloud/aws.yaml`](rules/cloud/aws.yaml) for a working example
and [`docs/development/writing-rules.md`](docs/development/writing-rules.md)
for the full schema.

```yaml
- id: aws-access-key-id
  name: AWS Access Key ID
  regex: '\b((?:AKIA|ASIA)[A-Z0-9]{16})\b'
  secret_group: 1
  keywords: [aws, access_key]
  negative_keywords: [example, placeholder]
  entropy: { enabled: false }
  severity: high
  confidence: 0.98
```

## Security

- **SSRF protections** are mandatory in the web scanner: DNS/IP
  validation before *and after* every redirect, with RFC1918,
  loopback, link-local, and the `169.254.169.254` cloud metadata
  endpoint blocked by default.
- **robots.txt is respected by default**; `--ignore-robots` is an
  explicit opt-in that prints a warning.
- **Remediation defaults to dry-run** and requires human approval —
  see [`docs/security/remediation.md`](docs/security/remediation.md).

Found a vulnerability? Please **do not** open a public issue — see
[`SECURITY.md`](SECURITY.md) for the private disclosure process.

## Roadmap

| Sprint | Focus | Status |
|---|---|---|
| 0 | Repository bootstrap | ✅ done |
| 1 | Detection engine (`cerberus scan file`) | ✅ done |
| 2 | Git + web scanners, distributed queue | ⏳ next |
| 3 | Local LLM validation (Ollama/llama.cpp) | planned |
| 4 | Cloud control plane (AWS) + MCP server | planned |
| 5 | AWS auto-remediation + hardening | planned |
| 6 | Production hardening + v1.0 launch | planned |

Full detail: [`ROADMAP.md`](ROADMAP.md) and the
[GitHub issue tracker](../../issues), organized by milestone.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the branching model, PR
requirements, and development setup. See
[`GOVERNANCE.md`](GOVERNANCE.md) for the project's decision-making
process.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
