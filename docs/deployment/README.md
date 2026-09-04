# Deployment

Three official profiles (see [ADR-0011](../adr/0011-deployment-profiles.md)
for the reasoning behind this split and its scoping):

- **[local.md](local.md)** — the `cerberus` CLI, standalone. No
  server, no database, no cloud dependency, `--offline` by default.
  Fully working today.
- **[team.md](team.md)** — Docker Compose: API/worker/MCP + Postgres +
  Ollama. Infrastructure is real; read the doc for exactly which
  pieces are still Sprint 4 stubs before assuming this is a working
  deployment.
- **[cloud.md](cloud.md)** — AWS via Terraform. Only the IAM role
  separation module (`deploy/terraform/modules/iam`) exists today;
  everything else (Lambda, Fargate, DynamoDB, KMS, EventBridge) is
  still planned — see the doc for what's real vs. not.

See also [`../architecture/overview.md`](../architecture/overview.md)
for the request-flow diagram.
