# ADR 0010: Remediation v2 — Plan/Execute separation, AWS disable-before-delete

Status: Accepted
Date: 2026-09-04

## Context

ADR-0003 established the *rule* that detection and remediation must be
architecturally separate — distinct components, distinct privileges,
connected only through `Finding → Plan → Approval → Execution`. Until
now `internal/remediation` only had the shapes of that rule (`Plan`,
`Status`, `Target`, `Planner`/`Executor` interfaces) with no real
implementation behind them, and `internal/remediation/aws` was an empty
stub. This ADR is where ADR-0003's promise gets real code.

Three things landed since ADR-0003 that this package now builds on:
Credential/Exposure correlation (`internal/credentials`), an
explainable risk engine (`internal/risk`), and a policy engine
(`internal/policyengine`) that already answers "how many approvals
does this remediation action need?" for a given provider/environment.
A `Plan` should be built *from* those — not re-invent risk scoring or
approval-counting logic inside `internal/remediation`.

## Decision

**Plan/Execute stay separate types and separate calls**, gated by an
explicit status machine (`transition.go`), not one "remediate now"
function:

```
Proposed ──▶ ApprovalRequired ──▶ Approved ──▶ Executing ──┬─▶ KeyDisabled ──▶ Verified ──▶ (KeyDeleted, future)
    │                                              │        └─▶ Failed ──▶ Executing (retry)
    └───────────────────────────▶ Approved          
(any of the above) ──▶ Cancelled
```

`CanTransition(from, to Status) bool` is the single source of truth for
which moves are legal; `Approve()` is the only function allowed to move
a `Plan` out of `ApprovalRequired`, and nothing in this package
self-approves. This mirrors why `internal/policyengine` only *decides*
and never *enforces* (ADR-0006): `DefaultPlanner.Plan` only *proposes*,
never executes, by construction — it has no field of any type that
could make a provider API call (no `IAMClient`, no HTTP client,
nothing). The compiler enforces this, not just code review.

**`Plan` gained `CredentialID` and `Risk cerberus.RiskAssessment`**,
extending rather than replacing the existing `Plan`/`Status`/`Target`
shapes from ADR-0003 (the existing `FindingID` field is kept for
backward audit-trail linkage; it's optional now, since a `Plan` is
built from a correlated `Credential`, not a single `Finding`
occurrence, matching the Credential/Exposure model this repo adopted
after ADR-0003 was written). Existing `Status` constants
(`PROPOSED`/`APPROVAL_REQUIRED`/`APPROVED`/... — the exact names
ADR-0003 already documents) are kept unchanged; `VERIFIED` is added as
a new terminal state for the re-confirmation step the spec asks for,
and `MONITORING`/`KEY_DELETED` stay defined-but-unreachable, reserved
for future async verification and the deferred delete step.

**`Planner.Plan`'s signature changed** from `Plan(findingID string)` to
`Plan(ctx context.Context, credential cerberus.Credential, exposures
[]cerberus.Exposure, action string) (Plan, error)`. Nothing in the tree
called the old signature (verified by grep before changing it) — this
is a clean alignment with the Credential/Exposure model, not a
compatibility break in practice. `DefaultPlanner`:
1. Calls `internal/risk.Assess(credential, exposures)` — pure, no I/O.
2. Calls `PolicyEngine.Evaluate` with `Domain: "remediation"` — decides
   `ApprovalsRequired`.
3. Returns a `Plan` in `ApprovalRequired` (if approvals are needed) or
   `Approved` (if the policy allows automatic execution) — never
   further than that.
A policy **denial** produces no `Plan` at all (an error instead) —
planning something nobody is allowed to run isn't a meaningful `Plan`
to hand back.

**AWS: disable-before-delete, enforced by omission.** `internal/remediation/aws.Executor`
implements exactly one privileged action — `UpdateAccessKey(...,
Inactive)` — followed by a synchronous re-read (`GetAccessKeyStatus`)
to confirm it took effect before promoting the `Plan` to `Verified`.
There is no delete code path in this package at all; "optional later
deletion" from the spec stays a documented gap, not a half-built
feature behind a flag.

**No AWS SDK dependency.** `aws.IAMClient` is this package's own
2-method interface (`UpdateAccessKey`, `GetAccessKeyStatus`) rather
than importing `aws-sdk-go-v2`. Every test in `internal/remediation/aws`
uses an in-memory fake implementing that interface — no test, anywhere
in this slice, can reach a real AWS account, matching the spec's
explicit rule against destructive tests on real accounts. A follow-up
slice wires `github.com/aws/aws-sdk-go-v2/service/iam`'s client behind
this same `IAMClient` shape; nothing else in `Executor` needs to
change.

**Idempotency, retry-safety, and scope-restriction are mechanisms, not
just claims:**
- *Idempotency*: `Execute` switches on `plan.Status` first.
  `Verified` → return unchanged, zero `IAMClient` calls. `KeyDisabled`
  → re-run verification only, never `UpdateAccessKey` again. Both are
  tested by asserting the fake's call counters stay at zero/unchanged.
- *Retry-safety*: `Approved` and `Failed` share one code path
  (`disableAndVerify`) — a `Plan` that failed transiently is retried by
  calling `Execute` again with the same `Plan`, no different from the
  first attempt. A verification mismatch or read error leaves the
  `Plan` at `KeyDisabled` (not `Failed`, not silently `Verified`) so a
  later `Execute` call safely re-checks without re-disabling.
- *Scope-restriction*: `Executor` is constructed with an explicit
  `authorizedAccountIDs` allowlist. `disableAndVerify` checks
  `plan.Target.AccountID` against it as the very first thing, before
  any `IAMClient` call — tested by asserting the fake records zero
  calls on an out-of-scope account. An `Executor` built with an empty
  allowlist authorizes nothing (fail-closed), not everything.
- *Never uses the discovered credential's own value*: structurally
  guaranteed — `cerberus.Credential` has no raw-secret field to begin
  with (ADR-0001), and `Executor`'s `IAMClient` is injected
  independently at construction time, never derived from the `Plan`
  it's executing.

## Consequences

- ADR-0003's diagram (`Scanner → Detector → Finding Store →
  Remediation Planner → Approval → Remediation Worker`) now has real
  code enforcing every arrow except the still-deferred pieces: no
  scan-triggered auto-planning wiring yet (that's `cmd/cerberus`
  wiring, deliberately left for a later step), no real AWS SDK calls
  yet, no delete action, no multi-party human-approval UI (`Approve()`
  just records a count — collecting that count from actual humans is
  a future control-plane/API concern, not this package's job).
- `internal/mcp`'s `RequestRemediationTool`/`ExecuteRemediationTool`
  (already merged) can now be wired to a real `DefaultPlanner`/`Executor`
  pair in a follow-up change without touching this package's public
  shape — that wiring is explicitly out of scope here per the task
  boundary (`cmd/cerberus/**` and `internal/mcp/**` were off-limits for
  this slice).
- Every `Plan` mutation this package performs carries a non-empty
  `Reason`, extending the same explainability convention as
  `cerberus.Signal`, `cerberus.RiskFactor`, and
  `policyengine.PolicyDecision` — a `Plan`'s current state is always
  answerable without reading logs.

## Alternatives considered

- **One `Remediate(credential)` call doing plan+approve+execute** —
  rejected: collapses exactly the boundary ADR-0003 exists to
  establish; an LLM or a buggy caller one call away from a live IAM
  mutation is the scenario ADR-0003 was written to prevent.
- **Delete access keys instead of/alongside disabling them** —
  rejected for this slice: disabling is reversible (an operator can
  re-enable a false-positive), matching the spec's explicit priority;
  deletion is destructive and only makes sense after a
  human-supervised monitoring window, which isn't built yet.
- **Wire a real AWS SDK now, gate real calls behind a `--dry-run`
  flag** — rejected: a flag is a runtime toggle a bug or a misconfigured
  default can silently flip; a fake-only test surface with the real
  SDK left for a deliberate follow-up is a compile-time guarantee
  instead of a runtime one.
- **Rename existing `Status` constants to match the spec's
  Draft/PendingApproval/Executed vocabulary exactly** — rejected:
  ADR-0003 already documents `PROPOSED`/`APPROVAL_REQUIRED`/`APPROVED`/
  etc. by name; renaming them would make that ADR stale for no
  functional benefit. Only `VERIFIED` was added, since no existing name
  covered the spec's re-confirmation step.
