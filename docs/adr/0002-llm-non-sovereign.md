# ADR 0002: The LLM is never sovereign

Status: Accepted
Date: 2026-09-03

## Context

Sprint 3 introduces optional local-LLM validation
(`cerberus.Validator`) for candidates that land in the
`[ThresholdLLMReview, ThresholdFinding)` scoring band. An LLM
classifying secrets necessarily processes untrusted, attacker-influenced
content (the scanned artifact itself), which makes prompt injection a
first-class threat, not an edge case.

## Decision

The LLM may only:

- raise or lower a candidate's score, within the ambiguous band;
- classify context (`likely_secret` / `likely_false_positive` /
  `uncertain`);
- produce a human-readable explanation for a finding;
- suggest a severity.

The LLM may never:

- delete or resolve a `CONFIRMED`/critical-severity finding on its own;
- trigger a remediation action directly — remediation is a fully
  separate pipeline (ADR-0003);
- hold cloud credentials or any remediation-capable permission;
- reach the network beyond the local model runtime (Ollama/llama.cpp);
- call tools of any kind (the validation prompt explicitly forbids
  tool use and network requests, and the runtime enforces egress-deny);
- receive a raw secret value — only `ValidationInput.RedactedContext`,
  which is sanitized (`internal/llm.Sanitize`) before the call is made.

`ValidationResult` is a schema-validated structured output, not free
text control flow: caller code interprets `Classification`/`Confidence`
as data, never as instructions.

## Consequences

- Cerberus works correctly with the LLM stage disabled entirely
  (`--offline` / no Ollama configured) — it is an accuracy enhancement,
  not a dependency.
- A successful prompt injection against the validator can at worst
  mis-score one candidate; it cannot escalate to remediation, exfiltrate
  other findings, or reach outside the sandboxed model runtime.
- The Sprint 3 quality gate (LLM stays opt-in unless it demonstrably
  improves precision without hurting recall on `testdata/corpus`) is a
  direct consequence: a component with this little authority still
  needs to earn its place by being measurably useful.

## Alternatives considered

- **Let the LLM directly emit/resolve findings** — rejected: collapses
  the deterministic/LLM boundary and makes prompt injection a
  detection-integrity issue instead of a bounded, low-blast-radius one.
- **Cloud LLM API instead of local-only** — rejected as the default:
  would send (even redacted) source content to a third party by
  default. Local-only keeps Cerberus usable in environments where that
  is unacceptable; a cloud adapter may be added later as an explicit,
  non-default opt-in.
