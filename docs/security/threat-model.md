# Threat model (v1)

This is a living document; expect revisions each sprint as new
attack surface is added (web crawling in Sprint 2, LLM in Sprint 3,
MCP/cloud in Sprint 4, remediation in Sprint 5).

## Assets

1. Secrets present in scanned content (the thing we must not leak).
2. Findings data (location, type, timing — sensitive but not
   equivalent to the secret itself, per [ADR-0001](../adr/0001-no-raw-secret-storage.md)).
3. The HMAC fingerprint key (compromise would allow offline
   fingerprint correlation/brute-forcing against known secret formats).
4. Remediation credentials (IAM roles capable of disabling/deleting
   cloud credentials).
5. The scanning infrastructure itself (compute, queues, MCP endpoint).

## Threat actors

- A malicious or compromised **scanned target** (a crafted repo, a
  malicious website/script) attempting to exploit the scanner.
- A malicious or compromised **MCP client / agent** attempting to
  escalate from read scopes to remediation.
- An external attacker attempting **SSRF** via the web scanner to reach
  internal services or cloud metadata endpoints.
- An insider or compromised credential attempting to **abuse
  remediation** to cause an outage (revoking a live credential) or to
  **exfiltrate findings**.

## Key mitigations (cross-referenced)

| Threat | Mitigation | Reference |
|---|---|---|
| Raw secret leaks via logs/storage/API | Fingerprint + mask only, never raw value | [ADR-0001](../adr/0001-no-raw-secret-storage.md) |
| Prompt injection via scanned content | LLM never sovereign, sanitized input, no tools/network | [ADR-0002](../adr/0002-llm-non-sovereign.md) |
| Detector bug escalating to remediation | Architectural + IAM separation | [ADR-0003](../adr/0003-remediation-separation.md) |
| SSRF / cloud metadata access via crawler | Mandatory DNS+IP validation before and after every redirect; block RFC1918/loopback/link-local/`169.254.169.254` | [`ssrf.md`](ssrf.md) (Sprint 2) |
| Compromised/malicious MCP agent | Scoped permissions, `cerberus_execute_remediation` isolated, approval required | [`../mcp/permissions.md`](../mcp/permissions.md) (Sprint 4) |
| Abusive/accidental remediation | Dry-run default, human approval, idempotency, rate limits | [`remediation.md`](remediation.md) (Sprint 5) |
| Supply-chain compromise | Pinned deps, SBOM, signed releases, `govulncheck`/`gosec` in CI | [`../development/release-process.md`](../development/release-process.md) (Sprint 6) |

## Out of scope for v1

- Multi-tenant isolation guarantees beyond basic RBAC (tracked for
  v1.3, "enterprise federation, advanced RBAC").
- Formal verification of the scoring model — mitigated instead by the
  benchmark corpus and precision/recall tracking.
