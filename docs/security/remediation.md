# Remediation security model

**Status: planned for Sprint 5** (`internal/remediation/aws`). See
[ADR-0003](../adr/0003-remediation-separation.md) for the architectural
rationale; this document covers the operational controls.

## Defaults

- `remediation.dry_run = true` — every plan is dry-run unless a human
  explicitly overrides it.
- `cerberus remediation apply <plan-id>` requires an explicit `--apply`
  flag *and* a plan already in `StatusApproved` — neither alone is
  sufficient.
- `ApprovalRequired` defaults to `true` on every generated `Plan`.

## Approval

- A `Plan` moves `PROPOSED → APPROVAL_REQUIRED → APPROVED` only via an
  explicit human action, recorded as an audit event
  (`REMEDIATION_APPROVED`, see [`audit.md`](audit.md)).
- Optional dual-approval and MFA constraints are configurable for
  higher-risk actions (e.g. deleting rather than disabling a key).
- Idempotency: re-approving or re-executing an already-`EXECUTING`/
  terminal-state plan must be a no-op, not a repeated action.
- Rate limits bound how many remediation actions can execute in a given
  window, to contain the blast radius of a false-positive storm or a
  compromised approver credential.

## Execution

- `remediation.Executor` refuses to act on any `Plan` not in
  `StatusApproved`.
- Execution follows: `AssumeRole` (scoped, time-limited) → disable key
  → alert (SNS/webhook/SIEM) → optional deletion later, never as the
  first action.
- Every execution attempt — success or failure — produces an audit
  event.

## Required tests before this is considered done

- Attempt to execute a `PROPOSED`/`APPROVAL_REQUIRED` plan directly →
  must fail closed.
- Attempt to re-execute a terminal-state plan → must be a no-op.
- Rate limit is enforced across concurrent execution attempts.
- IAM privilege-escalation check: the executor role cannot be used to
  grant itself broader permissions than configured.
