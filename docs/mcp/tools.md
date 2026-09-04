# MCP tools reference

`internal/mcp` exposes 12 tools through `Server.Dispatch`, the single
non-bypassable pipeline every call — read or mutating — passes
through:

```text
Authentication → Authorization → Policy → Scope validation →
Rate limiting → Audit → Execution
```

Authentication happens upstream of this package (the transport in
`internal/mcpserve` trusts whatever client connected with exactly the
scopes it was launched with — see `cerberus mcp serve --scope`).
Everything from Authorization onward runs the same way for every tool,
regardless of what the tool itself does. A caller can never grant
itself a scope by asking for it in the request (`ToolCall.RequestedScopes`
is informational/logging only) — the only source of truth is the
authenticated `Principal.GrantedScopes`. See
[ADR-0009](../adr/0009-mcp-v2.md) and [ADR-0002](../adr/0002-llm-non-sovereign.md).

List what a running server exposes at any time with:

```sh
cerberus mcp tools
```

Call one tool offline, through the real pipeline, without a live
transport:

```sh
cerberus mcp call --tool cerberus_get_finding --arg finding_id=f-123 \
  --scope findings:read
```

## Read-only tools

| Tool | Scope | Arguments | Returns |
|---|---|---|---|
| `cerberus_list_findings` | `findings:read` | `state`, `source_type`, `rule_id`, `limit` | `[]cerberus.Finding` matching the filter |
| `cerberus_get_finding` | `findings:read` | `finding_id` (required) | one `cerberus.Finding` |
| `cerberus_explain_finding` | `findings:read` | `finding_id` (required) | the finding's `cerberus.DetectionProvenance` — the same explanation `cerberus scan file --format explain` produces, never a separately computed one |
| `cerberus_list_credentials` | `credentials:read` | `provider`, `status`, `limit` | `[]cerberus.Credential` matching the filter |
| `cerberus_get_credential` | `credentials:read` | `credential_id` (required) | one `cerberus.Credential` |
| `cerberus_list_incidents` | `incidents:read` | `status`, `limit` | `[]cerberus.Incident` matching the filter |
| `cerberus_get_incident` | `incidents:read` | `incident_id` (required) | one `cerberus.Incident` |
| `cerberus_get_scan` | `scans:read` | `scan_id` | *not implemented* (see below) |

Every credential/finding/exposure/incident type returned here already
enforces "no raw secret value" structurally (ADR-0001) — a tool only
ever passes these domain types through unchanged.

## Mutating tools (not wired yet — honest stubs)

These are registered, scoped, and pass through the full pipeline, but
each `Handle` returns `IsError: true` with an explanatory message
instead of fabricating a result the codebase has no authority to back.
This is deliberate: the safety plumbing (scope check → policy → audit)
is exercised on the real tool shape now, rather than bolted on later
under pressure once the backing store exists.

| Tool | Scope | Arguments | Why it's a stub |
|---|---|---|---|
| `cerberus_start_scan` | `scans:start` | `source_type`, `target` | no scan-run store exists yet (`internal/queue` is publish/consume only) |
| `cerberus_cancel_scan` | `scans:cancel` | `scan_id` | same — no scan-run store |
| `cerberus_get_scan` | `scans:read` | `scan_id` | same — no scan-run store |
| `cerberus_request_remediation` | `remediation:request` | `credential_id` (required) | no `Planner` wired from credential → Finding → Plan yet (Phase K) |

## Privileged tool

| Tool | Scope | Arguments | Status |
|---|---|---|---|
| `cerberus_execute_remediation` | `remediation:execute` | `remediation_id` (required) | performs **no privileged action today** — no cloud credentials, no approved Plan/Executor wired in (Phase K) |

`cerberus_execute_remediation` is the tool the whole dispatch pipeline
exists for. It runs through the exact same six stages as every other
tool and holds no privileged credentials of its own — see
[ADR-0003](../adr/0003-remediation-separation.md). An LLM/agent must
never reach it → AWS IAM without external human authorization.

## Argument safety

`Tool.AllowedArguments()` is enforced centrally by `Dispatch`, not
trusted from the tool: a call carrying any key outside that list is
denied before `Handle` ever runs (`denied_arguments`). Mutating tools
only ever declare ID-shaped arguments (`finding_id`, `credential_id`,
`incident_id`, `remediation_id`) — never one that could carry a raw
secret value.

## Dispatch pipeline detail

For every call, `Server.Dispatch` runs, in order, denying at the first
stage that fails:

1. **Authorization** — `Principal.GrantedScopes` must cover every
   scope in `Tool.RequiredScopes()`.
2. **Policy** — `policyengine.PolicyEngine.Evaluate` is called with
   `Domain: "mcp", Action: "mcp:tool:<name>"`. `ApprovalsRequired > 0`
   is treated as not yet executable — the policy engine only decides
   the count, it never tracks or grants approvals itself (ADR-0006).
3. **Scope/argument validation** — see above.
4. **Rate limiting** — a per-principal token bucket
   (`internal/mcp.RateLimiter`), shared across every tool a principal
   calls, configured via `--rate-limit`/`--burst` (default: 5/s
   sustained, burst of 10). Idle buckets are evicted after 15 minutes.
5. **Audit** — every call, allowed or denied, is recorded
   (`mcp:tool_call:<name>`) before execution runs, so a denied attempt
   is never invisible to the audit trail. Audit failures never block
   the dispatch decision itself.
6. **Execution** — only reached if every prior stage passed.

Denials are always a `ToolResult{IsError: true, ErrorMessage: ...}` —
never a raw Go error a transport might leak verbatim.

## Running a server

- `cerberus mcp serve` — CLI-embedded stdio transport.
- `cerberus-mcp` (`cmd/cerberus-mcp`) — standalone binary for MCP
  client configs (Claude Desktop, Claude Code) that want to launch
  just the server.

Both wrap `internal/mcpserve.Run`, which seeds the findings/credentials
stores from `--findings`/`--correlate`, loads a policy from `--policy`
(empty = default-deny), and grants the scopes passed via repeatable
`--scope` flags for the lifetime of the process — this transport does
not authenticate per-request callers, so only run it where the
launching client is itself trusted with exactly those scopes.

```sh
cerberus mcp serve \
  --scope findings:read --scope credentials:read \
  --findings findings.json --correlate correlate.json \
  --policy policy.yaml --audit-log audit.jsonl
```

See also: [permissions.md](permissions.md) for the scope list and
default grants, and [ADR-0009](../adr/0009-mcp-v2.md) for the full
design rationale.
