# Security Policy

Cerberus handles credential detection and remediation. We take
security reports seriously and ask that you report vulnerabilities
privately.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Instead, use
[GitHub Security Advisories](../../security/advisories/new) for this
repository, which opens a private disclosure channel with maintainers.

Please include:

- a description of the vulnerability and its impact;
- steps to reproduce (a minimal repro is ideal);
- affected version(s)/commit;
- any suggested mitigation, if you have one.

## What counts as a security issue here

Examples specific to Cerberus's threat model (see
[`docs/security/threat-model.md`](docs/security/threat-model.md)):

- a way to make the web scanner reach a private/link-local address or
  the `169.254.169.254` cloud metadata endpoint (SSRF / DNS rebinding
  / redirect-based SSRF);
- a way to make a raw secret value end up in logs, traces, metrics,
  storage, or an API/MCP response;
- a way for LLM-supplied or scanned content to influence control flow
  outside the sandboxed validation call (prompt injection escalating
  to tool use, network access, or file access);
- an MCP authorization bypass, especially anything that lets a caller
  reach `cerberus_execute_remediation` without the required scope and
  approval;
- a way for the remediation executor to act without an `APPROVED` plan,
  or to escalate beyond its scoped IAM role;
- a supply-chain issue in the release/build/signing pipeline.

## Response process

1. We acknowledge new reports within 5 business days.
2. We aim to provide an initial assessment (severity, affected
   versions) within 10 business days.
3. We coordinate a disclosure timeline with the reporter once a fix is
   ready — typically alongside a patch release.

## Supported versions

Until 1.0.0, only the latest tagged pre-release receives security
fixes. After 1.0.0, see `ROADMAP.md` for the supported-versions table.
