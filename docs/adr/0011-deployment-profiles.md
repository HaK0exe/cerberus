# ADR 0011: Deployment profiles — LOCAL, TEAM, CLOUD

Status: Accepted
Date: 2026-09-04

## Context

Cerberus must not become an AWS-only tool — the spec is explicit that
a single analyst running the CLI, a team running Docker Compose, and
an organization running a managed AWS deployment are all first-class,
none of them a degraded version of another. Before this ADR, LOCAL
already worked (the CLI), but nothing codified TEAM (no Compose file)
or CLOUD (Terraform was a planning `README.md` with zero `.tf` files).

Two facts shape how far this slice goes:

1. `cmd/cerberus-api`, `cmd/cerberus-worker`, and `cmd/cerberus-mcp`
   are still Sprint 4 stubs — each prints a message and calls
   `os.Exit(1)`. `internal/storage` has no DynamoDB/Postgres/SQLite
   implementation. `internal/config` has no env-var/file-loading
   wiring (no `os.Getenv`, no `viper` calls anywhere in the tree at
   the time of writing).
2. This project has consistently refused to fabricate capability
   elsewhere — the credential-intelligence engine (ADR-0007) refused
   to guess an AWS account ID it couldn't honestly derive; the
   remediation executor (ADR-0010) uses a fake `IAMClient` in every
   test rather than pretend to talk to real AWS. Deployment tooling
   gets the same treatment: infrastructure for a service that doesn't
   run yet is scaffolding to be labeled as such, not a deployment
   guide implying it works end-to-end today.

## Decision

Three profiles, each scoped to what's honestly buildable and
verifiable right now:

- **LOCAL** (`docs/deployment/local.md`): documentation only. The
  CLI already does this; nothing to build.
- **TEAM** (`docs/deployment/team.md`, `deploy/docker/docker-compose.yml`):
  a real Compose file with `postgres`, `ollama`, and the three stub
  binaries, hardened per `deploy/docker/README.md`'s existing baseline
  (`read_only`, `cap_drop: [ALL]`, `no-new-privileges`), each
  documented per-service as working or stub. `postgres`/`ollama`
  genuinely start and are usable; the app containers build and exit
  immediately, `restart: "no"` so that's visible rather than
  crash-looping silently. This is legitimate infrastructure-readiness
  work — the topology, networking, volumes, and policy-mount path are
  ready for Sprint 4's application wiring to land into — but it is not
  represented as a working deployment today.
- **CLOUD** (`docs/deployment/cloud.md`, `deploy/terraform/modules/iam`,
  `deploy/terraform/environments/dev`): only the IAM role-separation
  module. See the next section for why this specific slice.

### Why Terraform starts with IAM, not the full stack

Three reasons converge on the IAM module as the right first slice:

1. **Highest security value per line of HCL.** It's the direct,
   concrete enforcement of ADR-0003 (scanner ≠ remediator) at the
   infrastructure layer — the same boundary `internal/architecture`'s
   Go test enforces in code, now enforced (to the extent Terraform
   can) in the roles that will eventually run that code in AWS.
2. **Safely reviewable and validatable without a live account.** IAM
   role/policy definitions are pure JSON-shaped documents Terraform
   can `validate` (schema/syntax) without ever calling AWS, and their
   correctness (right actions, right resources, right `Deny`) is
   reviewable by reading the HCL. Lambda/Fargate/API Gateway/DynamoDB
   configuration correctness is much harder to verify without actually
   deploying and exercising it — exactly the "don't fabricate what you
   can't test" trap this project avoids elsewhere.
3. **No compute/data layer exists yet to provision infrastructure
   for.** Standing up API Gateway + Lambda ahead of `cmd/cerberus-api`
   being real, or DynamoDB tables ahead of `internal/storage` having a
   DynamoDB backend, would be infrastructure nothing exercises — dead
   weight to maintain and a false signal of progress.

### The `Deny`-statement guarantee vs. the "nothing attached" guarantee

`CerberusWebScannerRole`/`CerberusGitScannerRole`/
`CerberusRemediationPlannerRole` get no policy attached — full stop.
That's enforced by *absence*: nothing in `modules/iam/main.tf` grants
them anything. Terraform has no built-in way to assert "and no future
change to this file may attach one either" (that needs policy-as-code
tooling evaluated in CI — `terraform-compliance` or Sentinel are the
usual choices; not added here, see Deferred below) — so this guarantee
rests on code review, the same way `internal/remediation`'s
side-effect-free `Planner` rests on "nothing in `DefaultPlanner`'s
struct holds an API client" being visible in the diff, not on a
compiler check.

`CerberusRemediationExecutorRole` is different: alongside its narrow
`Allow` (`iam:UpdateAccessKey`, `iam:ListAccessKeys`, both
resource-scoped), it carries an explicit `Deny` on
`iam:DeleteAccessKey`/`iam:CreateAccessKey`/`iam:CreateUser`/
`iam:DeleteUser`/etc. AWS IAM evaluates an explicit `Deny` as always
winning, over any `Allow` from any policy attached to that principal,
present or future. That makes this one guarantee durable and automated
in a way the "nothing attached" pattern isn't — deliberately placed on
the one role whose accidental over-permissioning would be most
dangerous (per the spec's own emphasis: disable before delete, and
never delete in this project's implementation at all yet).

## Consequences

- A team can `docker compose up` today and get a working Postgres +
  Ollama pair to build against, with the exact topology the eventual
  API/worker/MCP services will run in — without being misled into
  thinking findings persist or MCP is reachable yet.
- A future PR wiring `internal/storage`'s Postgres backend, or
  `internal/config`'s env/file loading, or `cmd/cerberus-api`'s actual
  HTTP server, drops into infrastructure that already exists rather
  than needing its own Compose/Terraform work bundled in.
- The IAM module gives reviewers (and, eventually, a security audit)
  something concrete to check ADR-0003's promise against, ahead of any
  running AWS workload.
- Nobody can accidentally `terraform apply` a partial Lambda/Fargate
  stack from this repo — because it isn't here yet.

## Alternatives considered

- **Build the full CLOUD stack now, stubbed with placeholder Lambda
  code** — rejected: untestable without a real account, high risk of
  silently-wrong IaC nobody would notice until first real deploy, and
  duplicates effort once the real Go services exist and the actual
  requirements (memory, timeout, IAM needs) are known.
- **Skip Terraform entirely until Sprint 4's application code lands**
  — rejected: the IAM module is valuable *now*, independent of
  application code, because it's a security boundary decision, not an
  implementation detail of a specific service.
- **`terraform-compliance`/Sentinel policy-as-code gate for the
  "scanner roles get no IAM permission" invariant** — deferred, not
  rejected: real value, but a new tooling dependency and CI wiring
  effort disproportionate to a single ADR's scope; worth doing once
  more Terraform exists for it to actually guard.
- **Docker Compose without the app-container stubs (just
  postgres+ollama)** — rejected: including the (currently inert) app
  containers, clearly labeled, documents the intended topology in one
  place rather than leaving it to prose alone, and costs nothing extra
  to maintain since their Dockerfiles already exist.
