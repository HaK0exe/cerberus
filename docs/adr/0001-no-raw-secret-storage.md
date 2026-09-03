# ADR 0001: No raw secret storage by default

Status: Accepted
Date: 2026-09-03

## Context

Cerberus's entire purpose is finding secrets. That makes it a uniquely
attractive target: a datastore full of the credentials it detected
would be a bigger prize than any single leak it prevents. We need a
storage model that lets operators triage, deduplicate, and act on
findings without Cerberus itself becoming a secret store.

## Decision

A `Finding` (`pkg/cerberus.Finding`) never carries the raw secret
value. Instead it carries:

- `Type` / `RuleID` / provider
- `Fingerprint` — HMAC-SHA256 of the secret under a server-side key
  (`internal/policy.Fingerprinter`), never a bare hash
- `MaskedPrefix` — a short, non-reversible visual hint (e.g.
  `AKIA****************`)
- `Length`, `Severity`, `Confidence`
- source location (`SourceType`, `SourceURI`, `Path`, `Commit`)
- `State`, timestamps, non-sensitive `Metadata`

This applies uniformly to logs, traces, metrics, the findings store,
audit records, and every API/MCP response. A raw candidate value may
exist transiently in memory during detection/LLM-review, and must be
zeroed (`internal/policy.Zero`) once it is no longer needed by that
specific buffer's owner.

We use a **keyed** HMAC rather than a bare `SHA256(secret)` because an
unkeyed hash over a low-entropy or structured secret space (e.g. a
predictable password format) is subject to offline correlation and
guessing attacks — see also ADR-0002 for the LLM cache key, which
inherits this same reasoning.

## Consequences

- Deduplication and re-identification of a previously-seen secret work
  via fingerprint comparison, without ever re-reading the value.
- Remediation workflows (Sprint 5) must re-derive what they need to act
  (e.g. the AWS Access Key ID, which is itself not secret) from
  metadata rather than from a stored raw value.
- A leaked findings database is an information-disclosure incident
  (locations, types, timing) but not a credentials-disclosure incident.
- The HMAC key becomes a sensitive piece of state in its own right —
  see `docs/security/threat-model.md` for its handling and rotation
  requirements (tracked for Sprint 4, once persistent storage exists).

## Alternatives considered

- **Store secrets encrypted with a KMS key, decrypt at triage time** —
  rejected: it would make Cerberus a viable secrets vault to attack,
  is unnecessary for the workflows we support (revoke, don't reuse),
  and complicates the audit story.
- **Store nothing beyond location, no fingerprint** — rejected:
  without a fingerprint, dedup/re-identification across scans would
  require re-scanning or storing the value; the fingerprint gives us
  correlation without exposure.
