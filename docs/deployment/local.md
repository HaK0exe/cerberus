# LOCAL profile

The `cerberus` CLI binary (`cmd/cerberus`, `deploy/docker/cerberus-cli.Dockerfile`)
already implements this profile end-to-end — nothing new was built for
it, this page documents what already runs.

## What runs

Just the `cerberus` binary, invoked per command. No server, no
database, no queue. Every command reads local files (or stdin) and
writes to stdout — state lives only for the duration of one invocation
(see each command's own doc comment for exactly what it reads/writes):

```bash
cerberus scan file path/to/file.env
cerberus scan file path/to/file.env --format explain   # per-signal score breakdown
cerberus git scan . --history
cerberus git scan . --format json | cerberus correlate --format json > correlated.json
cerberus correlate --input correlated.json --format text   # +risk +offline AWS intelligence
cerberus policy eval --policy my-policy.yaml --domain remediation --environment production --attr provider=aws
cerberus remediation plan --input correlated.json --credential-id cred_xxx --action disable_access_key --environment production --policy my-policy.yaml
cerberus mcp tools     # list the MCP tool surface (internal/mcp), no transport needed
cerberus mcp call --tool cerberus_list_credentials --correlate correlated.json --scope credentials:read
```

## What does NOT run

- No `cerberus-api`/`cerberus-worker`/`cerberus-mcp` process — those
  binaries are Sprint 4 stubs today regardless of profile (see
  `deploy/docker/README.md`).
- No Postgres/DynamoDB — `internal/storage` has no backend implemented
  yet; every store used by the CLI today (`internal/findings.MemStore`,
  `internal/credentials.MemStore`) is in-memory, scoped to one process
  invocation.
- No outbound network calls unless you explicitly point `cerberus web
  scan`/an Ollama-backed Validator at something — `--offline` defaults
  to `true` (see `cmd/cerberus/root.go`'s global flags).

## Local LLM (optional)

`internal/llm/ollama` and `internal/llm/llamacpp` are real Validator
adapters, wired into the detector for the ambiguous `llm_review` band
only (`internal/detector/detector.go`'s `WithValidator`). `cerberus
scan file` runs fully deterministic (regex + entropy + context) by
default; opt in with `--llm` (which also requires `--offline=false` —
cerberus never makes a network call, including to a local Ollama
server, unless you explicitly opt out of `--offline`):

```bash
cerberus scan file path/to/file.env --offline=false --llm \
  --llm-base-url http://localhost:11434 --llm-model llama3.1:8b \
  --llm-fallback-base-url http://localhost:8080   # optional llama.cpp fallback
```

Per `docs/architecture/llm-non-sovereign.md`: the LLM is never
required, never sees a raw secret (only redacted context via
`internal/llm.Sanitize`), and never has network egress beyond its own
local endpoint — nothing in this profile depends on cloud LLM access,
and a Validator failure (timeout, circuit open, unreachable) degrades
to the deterministic score, never blocks the scan.

## Fingerprint key stability

`cmd/cerberus/scan.go`'s `buildDetector` generates a fresh random HMAC
fingerprint key per invocation (see its own doc comment,
`TODO(sprint-4)`) — this means the same secret scanned twice in two
separate CLI invocations gets two *different* fingerprints today, so
cross-invocation deduplication (`cerberus correlate` across multiple
scans) only works within a single findings JSON file produced by one
scan, not across separately-run scans. A stable key needs a persisted
secret store, which is Sprint 4/TEAM-profile work — see
[team.md](team.md).
