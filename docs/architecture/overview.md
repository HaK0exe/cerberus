# Architecture overview

## Module map

```text
pkg/cerberus/          stable public domain types & interfaces
                        (Artifact, Candidate, Finding, Rule,
                        Detector, Validator, JobQueue, ScanOptions)
                        — no AWS/HTTP/MCP imports, ever.

internal/detector/      regex + entropy + context scoring engine
internal/rules/         YAML rule loader/compiler
internal/policy/        fingerprinting, masking, secret zeroing
internal/scanner/       scanner.Scanner contract
internal/scanner/git/   Git scanning (Gitleaks + native adapters — Sprint 2)
internal/scanner/web/   web crawling + SSRF guard (Sprint 2)
internal/llm/           Validator contract, sanitizer, cache — Sprint 3
internal/llm/ollama/    Ollama adapter — Sprint 3
internal/llm/llamacpp/  llama.cpp adapter — Sprint 3
internal/findings/      Finding store contract + in-memory implementation
internal/storage/       DynamoDB/S3-backed store — Sprint 4
internal/queue/         JobQueue contract + in-memory + SQS — Sprint 2/4
internal/mcp/           MCP server — Sprint 4
internal/remediation/   Plan/Planner/Executor contracts
internal/remediation/aws/ AWS provider — Sprint 5
internal/audit/         append-only audit sink contract
internal/config/        configuration loading
```

`pkg/cerberus` is the one package every other package may depend on.
Nothing in `internal/*` should depend on another `internal/*` package's
implementation details — only on `pkg/cerberus` and narrowly-scoped
contracts (e.g. `internal/detector` depends on `internal/rules` and
`internal/policy`, not the other way around).

## Detection pipeline

```text
Artifact
   │
   ▼
Preprocessor (normalization, encoding, extraction)
   │
   ▼
Regex rules (internal/rules)
   │
   ▼
Entropy filter (internal/detector.ShannonEntropy)
   │
   ▼
Context analysis (keyword/negative-keyword proximity)
   │
   ▼
Allowlist / suppression
   │
   ▼
Deterministic scoring (internal/detector.score)
   │
   ├── score ≥ 0.90 ──────────── Finding
   ├── score < 0.50 ──────────── Ignore
   └── 0.50 ≤ score < 0.90
            │
            ▼
        Local LLM validator (Sprint 3, optional)
            │
            ▼
        Final score → Finding
```

See [`scoring.md`](scoring.md) for the exact bands and
[`llm-non-sovereign.md`](llm-non-sovereign.md) for what the LLM stage
is and isn't allowed to do.

## Remediation pipeline

```text
Scanner → Detector → Finding Store → Remediation Planner → Approval → Remediation Worker
```

See [ADR-0003](../adr/0003-remediation-separation.md) for the
privilege-separation rationale and
[`remediation-separation.md`](remediation-separation.md) for the
runtime view.

## Deployment topologies

- **Local/CLI**: everything in-process, in-memory `JobQueue` and
  `findings.MemStore`, no network required (`--offline` is the
  default).
- **Cloud (AWS, Sprint 4+)**: API Gateway → Lambda (API) →
  SQS → Lambda/Fargate workers → DynamoDB, fronted by AWS WAF. See
  [`../deployment/aws.md`](../deployment/aws.md) (added in Sprint 4).
