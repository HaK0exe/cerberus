# MCP permissions

**Status: implemented** (`internal/mcp`, `internal/mcpserve`,
`cmd/cerberus-mcp`, `cerberus mcp`). See [tools.md](tools.md) for the
full per-tool reference.

## Scopes

```text
findings:read
credentials:read
incidents:read
scans:read
scans:start
scans:cancel

remediation:read
remediation:request
remediation:execute
```

`remediation:read` is defined but not yet required by any tool.

## Default grant

A remote MCP server grants, by default:

```text
findings:read
scans:read
```

No destructive or mutating capability is granted by default.

## Tools

Read-only tools:

```text
cerberus_list_findings
cerberus_get_finding
cerberus_explain_finding
cerberus_list_credentials
cerberus_get_credential
cerberus_list_incidents
cerberus_get_incident
cerberus_get_scan
```

Mutating tools, not wired to a real backing store yet — each returns
an honest "not available" error rather than a fabricated result (see
[tools.md](tools.md)):

```text
cerberus_start_scan
cerberus_cancel_scan
cerberus_request_remediation
```

Destructive tool, isolated on purpose (`remediation:execute` only),
also not wired to a privileged executor yet:

```text
cerberus_execute_remediation
```

## Mutating call pipeline

Every mutating MCP call passes through:

```text
Authentication → Authorization → Policy validation → Target scope
validation → Rate limit → Audit → Execution
```

An LLM/agent must never reach `cerberus_execute_remediation` → AWS IAM
without external human authorization — see
[ADR-0002](../adr/0002-llm-non-sovereign.md) and
[ADR-0003](../adr/0003-remediation-separation.md).
