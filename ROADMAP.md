# Roadmap

This is the condensed execution plan. Each sprint below maps to a
GitHub milestone with individual issues carrying priority, dependencies,
acceptance criteria, and estimates — see the
[issue tracker](../../issues) and [milestones](../../milestones).

## Recommended build order

```text
1. Domain model            8. Storage           15. AWS workers
2. Rules engine            9. Queue system       16. Remediation planner
3. Detector                10. API               17. AWS remediation
4. Test corpus             11. MCP               18. Audit
5. CLI                     12. Terraform         19. Observability
6. Git scanner             13. AWS workers       20. Hardening
7. Web scanner             14. Security bound.   21. Documentation
                                                  22. Release
```

Do not start with AWS, MCP, or a dashboard. The foundational pipeline —
`artifact → detector → finding` — is what everything else is built
around.

## Sprint 0 — Bootstrap (done)

Repository, LICENSE, README, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT,
CI skeleton, ADR template, issue templates.

## Sprint 1 — Detection engine (done)

`Artifact`/`Candidate`/`Finding`/`Rule`/`Detector`; regex + entropy +
context scoring + HMAC fingerprinting + allowlists; `cerberus scan
file`; initial TP/FP corpus; threat model v1; ADRs on secret storage,
LLM trust, remediation separation.

**Release:** `v0.1.0-alpha.1`

## Sprint 2 — Git & web scanners (weeks 3–4)

Git: working tree / staged / history via Gitleaks + native adapters,
SARIF output. Web: Colly-based crawler, scope/robots/depth/rate-limit,
SSRF guard (DNS+IP validation before and after every redirect hop),
JavaScript extraction. `JobQueue` interface with in-memory + SQS
implementations.

**Release:** `v0.1.0-alpha.2`

## Sprint 3 — Local LLM validation (weeks 5–6)

`Validator` interface, Ollama adapter, llama.cpp fallback, versioned
prompt templates, structured JSON output, HMAC-keyed response cache,
timeouts/circuit breaker. Egress-deny + no-tools sandboxing for the
LLM. Quality gate: LLM stays opt-in by default unless it demonstrably
improves precision without materially hurting recall on the corpus.

**Release:** `v0.2.0-alpha`

## Sprint 4 — Cloud control plane & MCP (weeks 7–8)

Terraform for API Gateway/Lambda/SQS/DynamoDB/KMS/CloudWatch/
EventBridge; web/git/finding-writer workers; MCP server
(`list_findings`, `get_finding`, `start_scan`, `get_scan`,
`cancel_scan`) with scoped auth; OpenTelemetry across the pipeline.

**Release:** `v0.3.0-beta`

## Sprint 5 — AWS remediation & hardening (weeks 9–10)

Account/identity resolution, `RemediationPlanner`/`RemediationExecutor`,
dry-run default, human approval (optional dual-approval + MFA),
idempotency, rate limits, SNS/webhook/SIEM alerting. Security review
pass across IAM, SSRF, MCP authorization, prompt injection, supply
chain, container hardening.

**Release:** `v0.5.0-beta`

## Sprint 6 — Productionization & launch (weeks 11–12)

Performance testing at scale, full documentation set, governance docs,
signed releases + SBOM + provenance, final security audit.

**Release:** `v0.9.0-rc1` → `v1.0.0`

## Post-v1 backlog

- **v1.1** — GitHub App, GitLab/Bitbucket integration, CI plugins,
  Slack/Teams alerts.
- **v1.2** — Azure/GCP remediation, Vault integration, Kubernetes,
  Docker image scanning.
- **v1.3** — multi-account AWS, policy packs, enterprise federation,
  advanced RBAC.
- **v2** — custom local classifier, WASM plugins, distributed rules
  registry, signed rule packs, feedback-assisted classification.

## Priorities

- **P0 (must have for v1):** detector, Git scanner, web scanner, SSRF
  protections, safe logging, fingerprints, CI/tests, LLM isolation,
  MCP RBAC, remediation separation, audit trail.
- **P1:** AWS serverless deployment, distributed crawling, SARIF,
  Ollama integration, AWS remediation, Terraform.
- **P2:** headless-browser crawling, llama.cpp, multi-provider
  remediation, dashboard, Kubernetes deployment.

## Versioning

Semantic Versioning for the overall project
(`0.1.0-alpha` → `0.2.0-alpha` → `0.3.0-beta` → `0.5.0-beta` →
`0.9.0-rc1` → `1.0.0`). Versioned **independently**: ruleset version,
prompt template version, MCP schema version, database schema version.

## Definition of Done — v1.0

- [ ] Git full-history scanning
- [ ] Secure web crawling (SSRF-hardened)
- [ ] JavaScript analysis
- [ ] Configurable rules
- [ ] Entropy/context scoring
- [ ] Ollama optional, no cloud LLM required
- [ ] MCP server functional with scoped permissions
- [ ] API functional
- [ ] Terraform AWS deployment
- [ ] Controlled AWS remediation (dry-run default, approval-gated)
- [ ] RBAC
- [ ] Append-only audit trail
- [ ] SBOM + signed binaries
- [ ] Fuzzing in CI
- [ ] Independent security review
- [ ] Benchmark corpus with published precision/recall
- [ ] Complete documentation set
- [ ] Open-source governance in place
