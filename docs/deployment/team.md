# TEAM profile

Docker Compose: `cerberus-api` + `cerberus-worker` + `cerberus-mcp` +
Postgres + Ollama, on one internal network. Config:
[`deploy/docker/docker-compose.yml`](../../deploy/docker/docker-compose.yml),
[`deploy/docker/docker-compose.env.example`](../../deploy/docker/docker-compose.env.example),
[`deploy/docker/policy.yaml`](../../deploy/docker/policy.yaml).

```bash
cp deploy/docker/docker-compose.env.example deploy/docker/.env
# edit deploy/docker/.env — at minimum set a real CERBERUS_DB_PASSWORD
# and CERBERUS_FINGERPRINT_KEY before anything beyond local testing
docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env up
```

## What actually works today

Read this before running the compose file — it is honest infrastructure
scaffolding for Sprint 4, not a working service, as of this writing:

| Service | Today |
|---|---|
| `postgres` | **Works.** Starts, passes its health check, ready to accept connections. |
| `ollama` | **Works.** Starts and serves the Ollama API on the internal network — usable directly, same as [local.md](local.md)'s `--llm` flag but pointed at `http://ollama:11434` from another container. |
| `cerberus-api` | **Stub.** `cmd/cerberus-api/main.go` prints "not implemented yet" and calls `os.Exit(1)`. The container builds and starts; the process inside exits immediately. `restart: "no"` in the compose file is deliberate — this must not crash-loop. |
| `cerberus-worker` | **Stub**, same as above (`cmd/cerberus-worker`). |
| `cerberus-mcp` | **Stdio-only.** The transport and scoped read tools work, while scan orchestration and remediation tools are explicit stubs. Compose cannot turn a stdio MCP process into a network service; use it from an MCP client configuration or use `cerberus mcp tools`/`cerberus mcp call` locally. |

## The Postgres gap

`internal/storage` has no DynamoDB/Postgres/SQLite implementation as
of this writing (check its current state before relying on this
document — it may have changed). Every store used by the CLI today
(`internal/findings.MemStore`, `internal/credentials.MemStore`) is
in-memory. The `postgres` service here is provisioned and reachable,
not yet written to by anything — standing up the database ahead of the
Go code that will use it is normal infrastructure sequencing, not a
claim that persistence works today.

## Environment variables

None of the variables in `docker-compose.env.example` are read by any
Go binary yet (`internal/config` has no env-var/viper wiring — grep
`os.Getenv\|viper\.` under `internal/` and `cmd/` to confirm before
relying on this). They're the intended interface the compose file
plumbs through to each container ahead of that wiring landing.

## Policy

`deploy/docker/policy.yaml` uses `internal/policyengine`'s native YAML
schema (same as `testdata/policy/example.yaml`) and is bind-mounted
into each service at `/etc/cerberus/policy.yaml`. `NativeEngine`
default-denies anything not explicitly listed — see
`docs/adr/0006-policy-engine.md`.

## Hardening

Every non-database/LLM container runs `read_only: true`,
`cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, matching
`deploy/docker/README.md`'s hardening baseline, and none of them are
exposed to a host port in this compose file (add one deliberately, per
service, once the corresponding binary is real) — see
`docs/adr/0011-deployment-profiles.md`.
