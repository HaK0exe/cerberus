# ADR 0007: Credential intelligence engine (offline, structural only)

Status: Accepted
Date: 2026-09-04

## Context

A `Credential` (ADR-0004) tells an analyst *that* a secret exists, how
many places it's been seen, and its declared provider/kind. It doesn't
yet answer richer triage questions — is this a long-term key or a
short-lived one, what account/org does it belong to, is it still live.
The project's plugin-architecture direction calls for a
`CredentialEnricher` extension point (`internal/intelligence`) that
adapters (AWS, GitHub, GCP, Vault, ...) plug into to answer those.

The project's own non-negotiable invariant governs how far that can go
today: *"Ne jamais valider une credential découverte en l'utilisant
directement contre un service tiers par défaut"* — never validate a
discovered credential by using it directly against a third-party
service by default. Cerberus is a scanner, not a credential-testing
tool; the moment enrichment means "try the key and see what happens",
Cerberus becomes an active participant in whatever damage that key can
do, and every enrichment call becomes a use-of-a-compromised-credential
event in its own right. This mirrors ADR-0001 (no raw secret storage)
and ADR-0003 (scanner/remediator privilege separation): the pattern
across this codebase is "the component that finds a secret never acts
as that secret."

## Decision

`internal/intelligence.CredentialEnricher` and every adapter under it
(starting with `internal/intelligence/aws`) are **offline and
side-effect-free by construction** in this slice: no network calls, no
`os/exec`, no SDK client that could reach a live service. An enricher
may only derive facts from:

1. Data already recorded on the `cerberus.Credential` it's given
   (`Provider`, `Kind`, timestamps, exposure count), or
2. In a future slice, an authorized, Cerberus-owned lookup API (e.g.
   AWS Organizations/IAM under Cerberus's *own* IAM role — not the
   discovered key) — out of scope here, tracked below.

`cerberus.Enrichment` is deliberately shaped to make this honest: there
is no `IsValid`/`IsActive` field, because this engine never learns
that. `Confidence` exists so an enricher that can only restate what the
caller already knew (e.g. echoing `Provider` back) reports a low
number instead of implying it added information it didn't.

### What `internal/intelligence/aws.Enricher` actually supports today

`rules/cloud/*.yaml` currently defines exactly two AWS rules:
`aws-access-key-id` and `aws-secret-access-key`. Because
`internal/detector.Detect` sets `Finding.Type` (and therefore, via
`internal/credentials.Correlate`, `Credential.Kind`) to the matching
rule's ID, `Kind` is the only per-credential signal available beyond
`Provider`. The AWS enricher uses it to report a `CredentialType`
(`access_key_id` vs. `secret_access_key`) — genuinely new structure,
if modest.

**It explicitly does NOT classify AWS access-key class** (long-term
IAM-user key vs. temporary STS session key vs. others), even though
the prefix taxonomy that distinction rests on (`AKIA`/`ASIA`/`AGPA`/
`AIDA`/`AROA`/... — all public, documented AWS conventions, and
already present verbatim in the `aws-access-key-id` rule's regex
alternation) is public knowledge. The reason is structural, not a gap
in the taxonomy: `cerberus.Credential` does not carry a `MaskedPrefix`
— that field exists on `Finding` only, and `internal/credentials.
Correlate` does not copy it onto the `Credential` it builds. Since this
slice's scope forbids touching `pkg/cerberus/credential.go` or
`internal/credentials/correlate.go`, the enricher has no honest way to
read the first four characters it would need. Fabricating a class from
`Kind` alone (which is identical — `"aws-access-key-id"` — for every
prefix) would be a guess dressed as a fact, which is exactly what
`Enrichment.Confidence` exists to prevent. This is recorded as a
`// TODO`-style boundary in the `aws` package's doc comment and covered
by `TestEnrich_DoesNotClaimKeyClass`, so a future change that threads
`MaskedPrefix` through the correlation step has both a documented
requirement and a regression test to update.

**AWS account-ID decoding**: not implemented, for the same honesty
reason plus lower confidence in the technique itself. Decoding an AWS
account ID from an access key ID relies on an undocumented internal
encoding (informally reverse-engineered by third parties, not an
AWS-published algorithm) that has drifted across key-ID eras. Shipping
a plausible-looking-but-possibly-wrong account ID next to a real
`Finding` is worse than not having the feature — an analyst could route
a revocation request to the wrong account. This is deferred, not
attempted; it isn't blocked by the `MaskedPrefix` gap above and could
be pursued later if a verified, current algorithm and test vectors are
sourced.

## Consequences

- `internal/intelligence.Registry` is the single place future adapters
  (`internal/intelligence/github`, `.../gcp`, `.../vault`, ...) plug
  into: implement `CredentialEnricher`, register it, done. No change
  to `Registry` or to callers of `EnrichAll` is needed to add one.
- Today's AWS enrichment is intentionally thin. The natural follow-up —
  propagate `MaskedPrefix` (or a narrower, purpose-built field) onto
  `Credential` so key-class classification becomes honestly derivable
  — is a `pkg/cerberus`/`internal/credentials` change, out of scope for
  this additive slice, and should land as its own reviewed change since
  it touches the domain model other in-flight work also depends on.
- A future *live*, authorized-API enrichment tier (AWS Organizations/
  IAM lookups under Cerberus's own role, never the discovered key) is
  a distinct trust tier from this one and should be its own
  `CredentialEnricher` implementation (e.g. `internal/intelligence/awsorg`)
  so a caller can choose to run only the offline tier, matching the
  spec's remediation-role separation pattern (ADR-0003).
- `Registry.EnrichAll` uses `errors.Join` so one failing/unavailable
  enricher doesn't blank out results from the others — enrichment is
  additive, best-effort information, not a pass/fail gate.

## Alternatives considered

- **Decode key class from `Kind` alone by inferring nothing and
  labeling every AWS access-key-id credential "unknown"** — this is
  effectively what was built; explicitly *not* building a
  seemingly-clever-but-wrong classifier from insufficient data was the
  deliberate choice here, not an oversight.
- **Add `MaskedPrefix` to `cerberus.Credential` in this same change** —
  rejected for this slice: it's a `pkg/cerberus`/`internal/credentials`
  change outside this slice's file boundary, and altering the shared
  domain model concurrently with sibling in-flight work (risk engine,
  policy engine) on the same files risks avoidable merge conflicts.
  Left as documented follow-up work instead.
- **Implement the AWS account-ID decode trick with a "best effort,
  unverified" disclaimer** — rejected: an unverified, silently-wrong
  fact attached to a security finding is worse than an absent one; see
  Decision above.
- **Make `CredentialEnricher.Enrich` allowed to opt into live checks
  via a flag** — rejected: a flag is one config change away from
  "on by default" and reintroduces the exact risk ADR-0001/0003 exist
  to prevent; a live-validation tier, if ever built, should be a
  structurally separate package/interface an operator must deliberately
  wire in, not a mode switch on this one.
