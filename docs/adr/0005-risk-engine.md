# ADR 0005: Risk engine, separate from detection confidence

Status: Accepted
Date: 2026-09-04

## Context

`internal/detector` already produces an explainable *detection
confidence* (`DetectionScore`, ADR/Phase C): how sure are we this
match is actually a secret? That number answers a narrow question and
answers it well, but analysts and remediation tooling need a different
question answered: given that this is a secret, and it is exposed
right now, *how bad is that*? A 0.98-confidence AWS key sitting in a
public JS bundle for six months is a different problem than the same
0.98-confidence AWS key found once in a private repo's working tree
five minutes ago — conflating the two into one number (as the spec
explicitly warns against: "Ne pas confondre Detection Confidence avec
Security Risk") would either under-alert on the first case or
over-alert on the second.

Risk also needs a wider input than a single `Finding`: it depends on
*how many places* a credential shows up (`Credential.ExposureCount`),
*where* (`Exposure.SourceType`/`Visibility`), *what kind* of secret it
is (`Credential.Provider`), and *how long* it's been sitting there
(`Credential.FirstSeen`) — all of which only exist once Phase B's
Credential/Exposure correlation has run. Risk is naturally a
downstream engine, not a detector-time concern.

## Decision

Add `internal/risk.Assess(cerberus.Credential, []cerberus.Exposure) cerberus.RiskAssessment`
as a pure, deterministic function, and `cerberus.RiskLevel` /
`cerberus.RiskFactor` / `cerberus.RiskAssessment` in `pkg/cerberus` as
the shared domain types (`docs/adr` convention: domain types in
`pkg/cerberus`, logic in `internal/*`).

Score is the **product** of six named, explainable factors — not a
sum, and not an opaque model:

```
RiskScore = credential_confidence × exposure_factor × visibility_factor
          × provider_factor × age_factor × reuse_factor
```

Multiplicative composition was chosen over the detector's additive
scoring because risk factors are naturally *amplifying*, not
*accumulating*: a public exposure doesn't add a fixed penalty
regardless of context, it multiplies whatever risk already exists from
reuse/age/provider. An additive model would let a maxed-out `age`
bonus alone push a single obscure, private, low-value exposure to
"critical" — multiplicative composition keeps every factor's effect
proportional to the others, and a factor's floor of `1.0` means "did
not move the score" rather than "did not exist", which keeps the
`Factors` list uniform and always fully explainable (see
`cerberus.RiskFactor` — every factor present always has a `Reason`,
never conditionally omitted).

Each factor is implemented in `internal/risk/risk.go` to be **honest
about what data actually exists today**, not to model the ideal formula:

- `credential_confidence` — **deliberately a no-op placeholder at
  1.0.** `Credential` (Phase B) does not retain the originating
  `Finding.Confidence`; `internal/credentials.Correlate` keeps
  identity and timestamps, not scores. Fabricating a confidence number
  here would silently misrepresent how sure Cerberus actually is.
  Deferred: extend `Correlate` to retain a representative (e.g. max)
  `Finding.Confidence` per `Credential`, then wire this factor to it.
- `exposure_factor` — `1.0 + 0.15 × min(exposureCount-1, 10)`: capped,
  diminishing-returns bonus per additional distinct location.
- `visibility_factor` — worst-case across all `Exposure`s (public web
  > unknown > private file/working-tree), since a credential is exactly
  as reachable as its most exposed location.
- `provider_factor` — a small hand-maintained lookup (cloud IAM
  providers > SCM/payment providers > everything else) approximating
  blast radius. **Deliberately not a `privilege_factor`**: the spec's
  formula includes one, but nothing in the codebase today can honestly
  answer "what can this specific key actually do" — that requires a
  credential-intelligence enricher (spec §7) that doesn't exist yet.
  Adding a privilege factor without that data would mean inventing a
  number; it's left out entirely rather than faked, and the ADR/spec
  formula in `internal/risk/risk.go`'s doc comment omits it
  accordingly.
- `age_factor` — bucketed by `time.Since(Credential.FirstSeen)`,
  monotonically non-decreasing, capped at 180+ days.
- `reuse_factor` — count of distinct `Exposure.SourceType` values,
  approximating "reuse across unrelated surfaces" (e.g. both git
  history and a public web bundle) as strictly worse than N
  near-duplicate findings within one surface.

The product is clamped to a documented `scoreCeiling` (10.0) before
mapping to a `RiskLevel` via fixed thresholds (`classify`), the same
pattern `internal/detector` uses for `ThresholdIgnore`/
`ThresholdLLMReview`/`ThresholdFinding` — explicit, named constants
next to a comment explaining they are calibration starting points, not
permanent.

## Consequences

- `Finding.Confidence` and `Credential`/`Incident` risk stay
  conceptually and structurally separate — nothing forces a caller to
  conflate "are we sure" with "how bad" the way a single blended score
  would.
- Every `RiskAssessment` is fully reconstructable from its `Factors`
  list without re-running `Assess` — same explainability contract as
  `DetectionProvenance`/`DetectionScore`.
- Because `credential_confidence` and (the omitted) privilege signal
  are currently placeholders/absent, today's `RiskAssessment.Score` is
  a real but incomplete risk signal — good enough to rank/triage
  relative exposures, not yet a substitute for an analyst's judgment on
  an individual incident. That gap is documented in code, not hidden.
- Adding real signals later (confidence wiring, a privilege_factor from
  a credential-intelligence enricher) is additive: append a factor to
  the `factors` slice in `Assess`, the product/threshold/explainability
  machinery does not change.

## Alternatives considered

- **Additive scoring, mirroring `internal/detector`** — rejected: risk
  factors amplify each other's effect (public + old + reused is worse
  than the sum of "public", "old", and "reused" independently);
  additive composition would require carefully hand-tuned weights to
  avoid one dominant term saturating the whole score regardless of
  context.
- **Single ML/black-box risk score** — rejected outright per the
  project's explainability requirement: an analyst (or an approval
  workflow gating remediation) must be able to see exactly which
  factors produced a score, not trust an opaque model. This also keeps
  the engine dependency-free and testable with simple, deterministic
  unit tests instead of a training/eval pipeline.
- **Fabricate `credential_confidence` from `Credential.Status` or
  `Kind` as a stand-in** — rejected: `Status`/`Kind` don't actually
  encode "how sure are we", and inventing a proxy would look
  authoritative while being arbitrary. A visible placeholder with a
  documented reason is more honest than a plausible-looking guess.
- **Include a `privilege_factor` populated by string-matching the
  `Kind`/rule ID (e.g. "contains 'admin'")** — rejected: this is
  exactly the kind of unverified guess the spec's credential
  intelligence engine (§7) exists to replace with a real enrichment
  call; a heuristic string match would be worse than omitting the
  factor, since it would look like real privilege data.
