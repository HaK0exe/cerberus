# Container images

| Image | Binary | Status |
|---|---|---|
| `cerberus-cli.Dockerfile` | `cerberus` | functional (Sprint 1) |
| `cerberus-api.Dockerfile` | `cerberus-api` | stub — Sprint 4 |
| `cerberus-worker.Dockerfile` | `cerberus-worker` | stub — Sprint 4 |
| `cerberus-mcp.Dockerfile` | `cerberus-mcp` | stub — Sprint 4 |

## Hardening baseline (all images)

- Multi-stage build; final image is `distroless/static-debian12:nonroot`
  — no shell, no package manager, no root user.
- `CGO_ENABLED=0`, statically linked, `-trimpath` to avoid leaking build
  paths.
- Run with `--read-only`, `--cap-drop=ALL`,
  `--security-opt=no-new-privileges`, and an explicit resource limit in
  any deployment (Compose/Kubernetes/ECS task definition) — not yet
  codified as a Compose file; tracked as a Sprint 4 follow-up alongside
  Terraform ECS task definitions.
- Images are scanned (Trivy/Grype), signed (Cosign), and shipped with
  an SBOM (Syft) as of Sprint 6 — see `docs/development/release-process.md`.

## Building locally

```bash
docker build -f deploy/docker/cerberus-cli.Dockerfile -t cerberus-cli .
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -v "$PWD/testdata:/data:ro" cerberus-cli scan file /data/corpus/true-positives/...
```
