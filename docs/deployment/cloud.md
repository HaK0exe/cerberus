# CLOUD/AWS profile

Target architecture per the roadmap: API Gateway + Lambda (API layer),
SQS (job fan-out — `internal/queue/sqs` already implements the Go side
of this), ECS/Fargate (long-running scan workloads: web/Chromium, Git
history — deliberately NOT Lambda, see below), DynamoDB (findings/
credentials/incidents/audit storage), KMS (per-concern keys), EventBridge
(scan scheduling/triggers), CloudWatch (logs/metrics), all provisioned
via Terraform (`deploy/terraform/`).

## Implemented today

Only the **IAM role separation module**:
[`deploy/terraform/modules/iam/`](../../deploy/terraform/modules/iam/),
called by [`deploy/terraform/environments/dev/`](../../deploy/terraform/environments/dev/).
See [`deploy/terraform/README.md`](../../deploy/terraform/README.md)
and [ADR-0011](../adr/0011-deployment-profiles.md) for why this is the
starting slice: it's the direct, concrete fulfillment of
[ADR-0003](../adr/0003-remediation-separation.md)'s scanner-never-
remediates rule, it's genuinely valuable to have as code before any
compute/data layer exists, and — unlike Lambda/Fargate/DynamoDB — it's
safely reviewable and `terraform validate`-able without a live AWS
account or any traffic flowing through it.

Seven roles, one per Cerberus component named in the original plan:
`CerberusAPIRole`, `CerberusWebScannerRole`, `CerberusGitScannerRole`,
`CerberusFindingWriterRole`, `CerberusRemediationPlannerRole`,
`CerberusRemediationExecutorRole`, `CerberusAuditRole`. The scanner
roles carry zero policy (no IAM/cloud-mutating permission of any
kind); the remediation planner role carries zero policy too (matching
`internal/remediation.DefaultPlanner`'s side-effect-free design, Phase
K); the remediation executor role gets exactly `iam:UpdateAccessKey` +
`iam:ListAccessKeys`, scoped by a resource-ARN variable, plus an
explicit, unconditional `Deny` on `iam:DeleteAccessKey`/
`iam:CreateAccessKey`/`iam:CreateUser`/`iam:DeleteUser` and friends —
the AWS-API-level mirror of `internal/remediation/aws.Executor`'s
disable-before-delete design (Phase K, `docs/adr/0010-remediation-v2.md`).

**Limitation, stated plainly**: Terraform cannot runtime-assert "this
role will never gain permission X in the future" the way
`internal/architecture`'s Go boundary test asserts "this package will
never import that one" — the module's guarantee for the scanner/planner
roles is "nothing is attached today, and changing that means editing
this file," which is a code-review/process guarantee, not an automated
one. The `Deny` statement on the executor role IS a durable, automated,
AWS-API-enforced guarantee (a `Deny` anywhere always wins), which is
why it exists specifically for the one role handling the destructive
action the spec is most explicit about bounding.

## Still planned (not implemented — do not assume these exist)

- **API Gateway + Lambda**: the API layer. `cmd/cerberus-api` is a
  Sprint 4 stub (`os.Exit(1)`) — no point deploying compute for code
  that doesn't run a server yet.
- **ECS/Fargate**: web (Chromium-capable) and Git-history scan workers.
  Per the spec, explicitly NOT Lambda — a headless-browser crawl or a
  large repository's full history is a poor fit for Lambda's execution
  model (cold starts, ephemeral disk, timeout ceiling); Fargate is the
  intended compute here. `cmd/cerberus-worker` is also a Sprint 4 stub
  today.
- **SQS**: `internal/queue/sqs` already exists on the Go side — no
  Terraform queue definition yet to back it in a real account.
- **DynamoDB**: tables planned per `deploy/terraform/README.md`
  (`cerberus-scans`, `cerberus-findings`, `cerberus-remediations`,
  `cerberus-audit`, `cerberus-cache`) — `internal/storage` has no
  DynamoDB implementation yet either (check its current state before
  relying on this document).
- **KMS**: per-concern keys (`alias/cerberus-data`,
  `alias/cerberus-audit`, `alias/cerberus-temporary-secrets`).
- **EventBridge / CloudWatch**: scheduling and observability — no
  metrics package exists in this repo yet to emit anything to
  CloudWatch from (see the metrics gap noted in earlier project audits).
- **`environments/prod/`**: only `environments/dev/` exists, and it
  only calls the `iam` module.
- **Policy-as-code enforcement** (e.g. `terraform-compliance`,
  Sentinel) for a stronger, automated version of the "scanner roles
  never get IAM permissions" guarantee than code review alone — noted
  as a future option in ADR-0011, not added (would be a new
  dependency/tooling requirement for a single slice).

Building any of the above ahead of the Go binaries that would actually
run behind it would be untested infrastructure for code that doesn't
exist — the same reasoning this project has applied consistently
elsewhere (no fabricated capability, no code path that can't be
exercised). Each piece lands once its corresponding application code
does.
