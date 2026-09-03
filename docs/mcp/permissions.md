# MCP permissions

**Status: planned for Sprint 4** (`internal/mcp`, `cmd/cerberus-mcp`).

## Scopes

```text
findings:read
scans:read
scans:start
scans:cancel

remediation:read
remediation:request
remediation:execute
```

## Default grant

A remote MCP server grants, by default:

```text
findings:read
scans:read
```

No destructive or mutating capability is granted by default.

## Tools

Read/plan tools (require the scopes above):

```text
cerberus_list_findings
cerberus_get_finding
cerberus_start_scan
cerberus_get_scan
cerberus_cancel_scan
cerberus_request_remediation
cerberus_get_remediation
```

Destructive tool, isolated on purpose (`remediation:execute` only):

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
