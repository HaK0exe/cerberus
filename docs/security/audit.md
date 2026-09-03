# Audit trail

`internal/audit.Sink` is append-only by design — the interface exposes
no update or delete method. Every sensitive operation (remediation
approval/execution, scope/RBAC changes, MCP-triggered mutations)
records an `audit.Event`:

```json
{
  "actor": "alice@example",
  "action": "REMEDIATION_APPROVED",
  "resource": "rem_123",
  "timestamp": "...",
  "request_id": "...",
  "result": "success"
}
```

`Event.Metadata` must never contain a secret value, authorization
header, cookie, session token, Git credential, or private key content
— the same rule as [logging](#logging-vs-audit) below.

## Logging vs. audit

- **Logs** (`slog`, JSON format) are for operational visibility:
  timestamps, service, scan/finding IDs, event names. Never the secret
  value or credentials in transit.
- **Audit** is specifically for sensitive, attributable actions taken
  by a human or system actor, and is expected to be retained longer and
  treated as tamper-evident (S3 Object Lock is optional for the audit
  archive — see `ROADMAP.md` §29 S3).

`audit.NopSink` exists only for tests where audit is explicitly
irrelevant — it must never be wired as a production default.
