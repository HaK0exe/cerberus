# Container images

| Image | Binary | Status |
|---|---|---|
| `cerberus-cli.Dockerfile` | `cerberus` | functional (Sprint 1) |
| `cerberus-api.Dockerfile` | `cerberus-api` | stub — Sprint 4 |
| `cerberus-worker.Dockerfile` | `cerberus-worker` | stub — Sprint 4 |
| `cerberus-mcp.Dockerfile` | `cerberus-mcp` | stdio transport; scan/remediation tools remain stubs |

## Hardening baseline (all images)

- Multi-stage build; final image is `distroless/static-debian12:nonroot`
  — no shell, no package manager, no root user.
- `CGO_ENABLED=0`, statically linked, `-trimpath` to avoid leaking build
  paths.
- Run with `--read-only`, `--cap-drop=ALL`,
  `--security-opt=no-new-privileges`, and explicit resource limits in
  any deployment. The first three are codified for application
  containers in [`docker-compose.yml`](docker-compose.yml); resource
  limits remain deployment-specific (see
  [docs/deployment/team.md](../../docs/deployment/team.md)); an ECS
  task definition equivalent is still a Sprint 4 follow-up alongside
  the rest of `deploy/terraform`.

## TEAM profile (docker-compose)

```bash
cp deploy/docker/docker-compose.env.example deploy/docker/.env
# edit deploy/docker/.env first — see docs/deployment/team.md for what
# actually works today vs. what's still wired up ahead of Sprint 4
docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env up
```
- Container scanning, signing, and image SBOM publication are not yet
  part of the release workflow. The current workflow secures CLI
  archives; see `docs/development/release-process.md`.

## Building locally

```bash
docker build -f deploy/docker/cerberus-cli.Dockerfile -t cerberus-cli .
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -v "$PWD/testdata:/data:ro" cerberus-cli scan file /data/corpus/true_positive/aws-access-key-id_basic.env
```
