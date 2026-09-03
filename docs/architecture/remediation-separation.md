# Remediation separation

See [ADR-0003](../adr/0003-remediation-separation.md) for the full
decision record. Summary: scanners/detectors hold zero
credential-mutating permissions; `remediation.Planner` may hold
read-only credentials; only an approved `Plan` (`StatusApproved`) may
be executed, and only `remediation.Executor` — running under a
separate, more privileged IAM role in cloud deployments
(`CerberusRemediationExecutorRole`) — is allowed to hold write
credentials.

```text
Scanner → Detector → Finding Store → Remediation Planner → Approval → Remediation Worker
```

`remediation.Plan.DryRun` defaults to `true`; `cerberus remediation
apply` requires an explicit `--apply` flag on top of an already-approved
plan (see [`../security/remediation.md`](../security/remediation.md)).
