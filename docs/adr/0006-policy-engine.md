# ADR 0006: Policy engine

Status: Accepted
Date: 2026-09-04

## Context

Several control-plane decisions in the roadmap are structurally the
same question — "is this action allowed, and under what conditions?"
— asked in different domains: how many human approvals a remediation
action needs before it can execute (ADR-0003), which scopes an MCP
caller may invoke (ADR-0002's "the LLM is never sovereign" extends to
any MCP client), whether a web scan should obey `robots.txt`. Left
unmanaged, each of these becomes its own scattered set of `if`
statements inside `internal/remediation`, `internal/mcp`, and
`internal/scanner/web` — hard to audit as a whole, easy to get
subtly inconsistent (e.g. one path defaulting open, another closed),
and impossible to reconfigure without a code change.

## Decision

A single interface:

```go
type PolicyEngine interface {
    Evaluate(ctx context.Context, input PolicyInput) (PolicyDecision, error)
}
```

`PolicyInput` is a flat `{Domain, Action, Environment, Attributes
map[string]string}` rather than a per-domain struct, so `remediation`,
`mcp`, and `scan` (and future domains — retention, severity) share one
interface instead of multiplying interfaces per domain. `Attributes`
is intentionally a generic string map, not a fixed schema: what it
contains is domain-specific (`provider`/`environment` for
remediation, `scope` for MCP), and only the native engine's `Policy`
struct needs to know the shape. This keeps `PolicyEngine` itself
stable as new domains are added.

`PolicyDecision.Reason` is **never empty** — allow, deny, and
approval-required decisions must all be explainable, mirroring
`cerberus.Signal.Reason` in the detection-scoring engine (ADR — see
`pkg/cerberus/provenance.go`). A policy engine that can say "no" (or
"yes, but...") without saying why is not meaningfully auditable.

**Definition / evaluation / enforcement are three separate concerns,
kept separate on purpose:**

- *Definition* — the YAML `Policy` document (`internal/policyengine/native.go`),
  loaded once, holding only data.
- *Evaluation* — `NativeEngine.Evaluate`, a pure decision function:
  input in, `PolicyDecision` out, no side effects.
- *Enforcement* — deliberately **not** in this package. Nothing here
  blocks an HTTP request, denies an MCP tool call, or halts a
  remediation execution. That responsibility belongs to the callers
  in `internal/mcp` (MCP v2), `internal/remediation` (Remediation v2),
  and `internal/scanner/web` once they're wired to call `Evaluate`
  and act on the result — this ADR only establishes the decision
  point they'll call into.

**Default-deny.** Any `Domain`/`Action`/attribute combination with no
matching rule — including an entirely empty or missing policy
document — is denied, with a `Reason` explaining that nothing matched.
This mirrors the posture in ADR-0001/0003: an unconfigured
control-plane decision must fail closed. A misconfigured or absent
policy file must never be silently read as "everything is allowed" —
that would turn a deployment mistake into an authorization bypass.

**Native YAML first, OPA/Rego as an optional later backend.** The
spec explicitly allows this staging. `PolicyEngine` is already the
seam: a future `internal/policyengine/opa` package implementing the
same interface (e.g. backed by `github.com/open-policy-agent/opa/rego`)
could be swapped in via the same constructor pattern, without touching
`PolicyInput`/`PolicyDecision` or any caller. Building the Rego
integration now, before there is a single real caller exercising the
interface, would be premature — the native engine is small enough
(three domains, ~150 lines) to stay simple and auditable, and is
exactly what's needed for the callers that exist today.

The YAML schema is intentionally minimal — three structs
(`RemediationRule`, `MCPPolicy`, `ScanPolicy`), no general-purpose
condition/expression language:

```yaml
remediation:
  - provider: aws
    environment: production
    automatic: false
    approvals_required: 2
  - provider: aws
    environment: development
    automatic: true

mcp:
  allow:
    - findings:read
    - scans:read

scan:
  obey_robots_txt: true
```

`RemediationRule` matches are exact (`provider` + `environment`),
evaluated in document order — the schema does not support wildcards
or precedence rules yet. That's a deliberate simplicity/coverage
trade-off, not an oversight: today's three domains don't need more
than exact matching, and adding a matcher language is easy to defer
until a real policy needs it.

## Consequences

- `internal/remediation`, `internal/mcp`, and `internal/scanner/web`
  each gain one call site (`Evaluate`) instead of ad hoc conditionals,
  once wired in (MCP v2 / Remediation v2 / scan hardening — future
  work, not done by this ADR).
- A policy change (e.g. requiring 3 approvals in production instead of
  2) becomes a YAML edit, not a code change and redeploy.
- `ApprovalsRequired` is advisory data on an `Allow: true` decision,
  not itself an approval gate — `NativeEngine` never tracks or grants
  approvals; that state lives in the remediation approval workflow
  (ADR-0003). A caller must not treat `Allow: true` with
  `ApprovalsRequired > 0` as "proceed immediately."
- Every unconfigured domain/action/environment fails closed, which
  means turning on a new automated capability always requires an
  explicit policy entry — slightly more setup friction, in exchange
  for no silent auto-allow.

## Alternatives considered

- **Per-domain interfaces** (`RemediationPolicy`, `MCPPolicy`,
  `ScanPolicy` as separate Go interfaces) — rejected: multiplies
  boilerplate for callers and defeats the point of a *common* engine;
  the spec explicitly asks for one `PolicyEngine.Evaluate`.
- **OPA/Rego from day one** — rejected for now: adds a dependency and
  a second language (Rego) before there's a caller to justify it. The
  interface boundary already makes this an additive migration later
  rather than a rewrite.
- **Default-allow with an explicit deny-list** — rejected: safer
  default for a security tool's own control plane is fail-closed; an
  operator forgetting to configure a domain should not accidentally
  grant it, especially for `remediation` and `mcp`.
- **Free-form rule expressions in YAML** (e.g. a tiny embedded
  expression language for `Attributes` matching) — rejected as
  premature: none of today's three domains need more than exact
  field matching; adding an expression language now would be
  speculative complexity with no consumer.
