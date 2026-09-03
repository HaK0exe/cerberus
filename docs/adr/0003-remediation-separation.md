# ADR 0003: Detection and remediation are architecturally separate

Status: Accepted
Date: 2026-09-03

## Context

Cerberus can, in later sprints, act on what it finds (e.g. disabling a
leaked AWS access key). Any code path that finds secrets is exposed to
untrusted, attacker-influenced input (scanned files, crawled web pages,
Git history). If that same code path also held credential-revoking
privileges, a bug or injection in detection would become a privilege
escalation into the target's cloud account.

## Decision

Detection and remediation are split into distinct components running
under distinct IAM roles/process privileges, connected only through the
`Finding` → `Plan` → `Approval` → `Execution` pipeline:

```text
Scanner → Detector → Finding Store → Remediation Planner → Approval → Remediation Worker
```

- **Scanners and detectors** hold no IAM-mutating, GitHub-mutating,
  Vault-mutating, or other administrative permissions. They can only
  produce `Finding`s.
- **`remediation.Planner`** may hold *read-only* credentials (e.g. to
  resolve which AWS account/IAM identity a key belongs to) and produces
  a `Plan` in `PROPOSED`/`APPROVAL_REQUIRED` state — never
  self-transitions to `APPROVED`.
- **Approval** is a distinct step, performed by a human (optionally
  requiring dual approval / MFA per `docs/security/remediation.md`).
- **`remediation.Executor`** is the only component allowed to hold
  write credentials (e.g. `iam:UpdateAccessKey`), and must refuse to
  act on any `Plan` not in `StatusApproved`.
- `remediation.Plan.DryRun` defaults to `true`; the CLI requires an
  explicit `--apply` flag, and execution still requires an
  independently-approved plan even then.

In IAM terms (Sprint 4+): `CerberusWebScannerRole` /
`CerberusGitScannerRole` never carry the permissions granted to
`CerberusRemediationPlannerRole` / `CerberusRemediationExecutorRole`.

## Consequences

- A vulnerability in the web or Git scanner (parsing untrusted content)
  cannot, by construction, reach credential-revoking APIs — there is no
  code path, and in cloud deployments no IAM permission, connecting
  them.
- Every remediation action produces an audit event and requires a
  distinct human decision point, at the cost of removing single-click
  "auto-fix" from the product's default behavior. This is intentional:
  auto-revoking a credential can itself cause an outage.
- MCP exposes `cerberus_execute_remediation` as a separate, more
  tightly-scoped tool from the read/plan tools, mirroring this split at
  the agent-interface layer (see ADR-0002 for why an LLM/agent must
  never reach this tool without external authorization).

## Alternatives considered

- **Single privileged service does detection + remediation** —
  rejected: simpler to build, but collapses the security boundary this
  ADR exists to establish.
- **Remediation always fully automatic (no approval gate)** —
  rejected: not acceptable as a default given the outage risk of a
  false-positive-triggered revocation; may be offered later as an
  explicit, scoped opt-in for specific low-risk actions.
