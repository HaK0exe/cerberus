# Terraform (planned — Sprint 4)

This directory will hold the AWS deployment IaC:

```text
deploy/terraform/
├── modules/
│   ├── api-gateway/
│   ├── lambda/
│   ├── sqs/
│   ├── dynamodb/
│   ├── kms/
│   ├── ecs-fargate/
│   └── iam/            # CerberusAPIRole, CerberusWebScannerRole,
│                        # CerberusGitScannerRole, CerberusFindingWriterRole,
│                        # CerberusRemediationPlannerRole,
│                        # CerberusRemediationExecutorRole, CerberusAuditRole
└── environments/
    ├── dev/
    └── prod/
```

Key constraints these modules must satisfy (see
[ADR-0003](../../docs/adr/0003-remediation-separation.md) and
[`../../docs/architecture/overview.md`](../../docs/architecture/overview.md)):

- `scanner != remediator`: no IAM role used by a scanner/worker may
  carry any permission granted to
  `CerberusRemediationPlannerRole`/`CerberusRemediationExecutorRole`.
- Separate KMS keys per concern: `alias/cerberus-data`,
  `alias/cerberus-audit`, `alias/cerberus-temporary-secrets` — not one
  universal key.
- S3 buckets: Block Public Access on, SSE-KMS, lifecycle policies;
  Object Lock optional for the audit archive.
- DynamoDB tables: `cerberus-scans`, `cerberus-findings`,
  `cerberus-remediations`, `cerberus-audit`, `cerberus-cache`.

Nothing is implemented here yet — see the "Sprint 4 — Cloud control
plane & MCP" milestone in the issue tracker.
