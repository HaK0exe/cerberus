# ADR 0004: Credential/Exposure/Incident model

Status: Accepted
Date: 2026-09-04

## Context

Prior to this change, every `Finding` was treated as an independent
unit: the same AWS access key checked into three commits and echoed
into a public JS bundle produced five unrelated findings. That makes
triage noisy and makes it impossible to answer the questions an
analyst actually asks first: *how many unique secrets are exposed?*,
*where else does this one show up?*, *is it still publicly reachable?*

We need a model that separates "a detection occurred here" from "this
is one secret, reused/leaked in N places" without discarding the
per-occurrence detail a `Finding` already carries.

## Decision

Introduce three additive types in `pkg/cerberus` on top of the
existing `Candidate` → `Finding` pipeline:

- **`Credential`** — the logical identity of one secret value,
  correlated by `Finding.Fingerprint` (the existing keyed HMAC from
  ADR-0001). Carries provider/kind, first/last seen, exposure count,
  and lifecycle status. Never carries the raw secret or the reversible
  means to reach it.
- **`Exposure`** — one distinct location a `Credential` was observed
  at (source type/URI/path/commit). A `Credential` with more than one
  `Exposure` has been duplicated or reused.
- **`Incident`** — groups a `Credential`'s `Exposure`s for triage, risk
  scoring, and remediation. Kept 1:1 with `Credential` for now; nothing
  in the shape prevents a future policy from merging incidents across
  related credentials.

Correlation (`internal/credentials.Correlate`) is a **pure, stateless
function**: `[]Finding → ([]Credential, []Exposure, []Incident)`. IDs
are derived deterministically (`sha256` of a namespaced string over the
fingerprint / credential+location / credential), never randomly
generated, so re-running correlation over a growing finding set is
idempotent — the same secret always produces the same `Credential.ID`,
and `MemStore.PutAll` upserts safely on repeated calls. This mirrors
how `Finding.Fingerprint` itself must be a keyed HMAC, not a bare hash,
and keeps `Credential.ID` distinct from the fingerprint it's derived
from — the ID is never treated as, or exposed as, a substitute for the
underlying secret's identity outside Cerberus's own storage.

`Finding` is unchanged and keeps its existing meaning: the
per-occurrence record a `Detector` emits. `Credential`/`Exposure` are
built *from* findings, not instead of them — the audit trail of "what
did we detect and when" stays intact.

## Consequences

- Analysts get "how many unique credentials" and "where else was this
  one seen" for free from the correlation step, without a global
  database — it works today over a single `Findings` JSON file via
  `cerberus correlate`, and will work continuously against the finding
  store once the API/persistence layer (Sprint 4) lands.
- Every later phase that assumes a credential graph — risk scoring,
  credential intelligence/enrichment, remediation targeting — can be
  built against `Credential`/`Exposure`/`Incident` instead of raw
  `Finding` lists.
- `internal/credentials.MemStore` intentionally is not a single
  `Store` interface with overloaded `Put`/`Get`/`List` methods across
  `Credential`/`Exposure`/`Incident` — Go doesn't support overloading,
  so `ExposureStore`/`IncidentStore` use distinct method names
  (`PutExposure`, `PutIncident`, ...) so one memory-backed type can
  satisfy all three store interfaces cleanly.
- `cerberus credentials`/`cerberus incidents` list/get remain
  server-only stubs, consistent with `cerberus findings` today — the
  CLI has no long-lived process to hold correlated state between
  invocations until Sprint 4.

## Alternatives considered

- **Fold `Credential`/`Exposure` fields directly onto `Finding`** —
  rejected: conflates "one detection event" with "one logical secret,
  N occurrences", and would force every downstream consumer to
  re-derive the grouping themselves instead of once, centrally.
- **Random (UUID) IDs for `Credential`/`Exposure`/`Incident`** —
  rejected: breaks idempotent re-correlation — the same secret would
  mint a new `Credential` on every run unless something else tracked
  fingerprint→ID mappings persistently, which the deterministic-hash
  scheme gives for free without extra state.
- **N:M `Incident`↔`Credential` from day one** — deferred, not
  rejected: the 1:1 shape today is the simplest thing that satisfies
  the spec's `Incident.CredentialID string` field; nothing about the
  correlation function's boundary blocks introducing multi-credential
  incidents later behind a policy decision.
