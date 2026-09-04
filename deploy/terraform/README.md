# Terraform

See [docs/deployment/cloud.md](../../docs/deployment/cloud.md) for the
full CLOUD profile plan and what's implemented vs. still planned.

## Implemented today

```text
deploy/terraform/
├── modules/
│   └── iam/            # CerberusAPIRole, CerberusWebScannerRole,
│                        # CerberusGitScannerRole, CerberusFindingWriterRole,
│                        # CerberusRemediationPlannerRole,
│                        # CerberusRemediationExecutorRole, CerberusAuditRole
└── environments/
    └── dev/             # calls modules/iam only
```

The `iam` module is the first concrete enforcement of
[ADR-0003](../../docs/adr/0003-remediation-separation.md)'s
scanner-never-remediates rule at the infrastructure layer: each role is
separate, scanner roles carry zero IAM/cloud-mutating permissions, and
`CerberusRemediationExecutorRole` gets only `iam:UpdateAccessKey` +
`iam:ListAccessKeys`, plus an explicit `Deny` on
delete/create-identity actions. See
[docs/adr/0011-deployment-profiles.md](../../docs/adr/0011-deployment-profiles.md)
for the full reasoning and its limits (Terraform can't runtime-assert
"this role can never gain a permission later" the way
`internal/architecture`'s Go boundary test does — that's a process/review
guarantee here, not an automated one).

Validate with `terraform fmt -check` and, network permitting,
`terraform validate` from `environments/dev/`.

## Still planned (not in this repo yet)

```text
modules/
├── api-gateway/
├── lambda/
├── sqs/
├── dynamodb/
├── kms/
└── ecs-fargate/
environments/
└── prod/
```

Key constraints these modules must satisfy when they're built (see
[ADR-0003](../../docs/adr/0003-remediation-separation.md) and
[`../../docs/architecture/overview.md`](../../docs/architecture/overview.md)):

- Separate KMS keys per concern: `alias/cerberus-data`,
  `alias/cerberus-audit`, `alias/cerberus-temporary-secrets` — not one
  universal key.
- S3 buckets: Block Public Access on, SSE-KMS, lifecycle policies;
  Object Lock optional for the audit archive.
- DynamoDB tables: `cerberus-scans`, `cerberus-findings`,
  `cerberus-remediations`, `cerberus-audit`, `cerberus-cache`.
- Per the spec: don't force the wrong compute model — Chromium-based
  web scanning and Git-history scanning belong on Fargate, not crammed
  into Lambda; the API layer is the Lambda-appropriate piece.

Nothing beyond the `iam` module is implemented here yet — the
`cerberus-api`/`cerberus-worker`/`cerberus-mcp` Go binaries are still
Sprint 4 stubs (see `deploy/docker/*.Dockerfile`), so standing up
Lambda/Fargate/API Gateway ahead of them would be untestable
infrastructure for code that doesn't exist yet.
