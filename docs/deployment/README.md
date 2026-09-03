# Deployment

- **Local / CLI**: `go build ./cmd/cerberus` or the
  `deploy/docker/cerberus-cli.Dockerfile` image — no network or cloud
  dependency, `--offline` by default.
- **AWS (Sprint 4+)**: Terraform-managed serverless deployment — see
  [`../../deploy/terraform/README.md`](../../deploy/terraform/README.md)
  for the module layout and constraints, and
  [`../architecture/overview.md`](../architecture/overview.md) for the
  request-flow diagram. A full `aws.md` deployment guide lands with
  Sprint 4.
