# Governance

Cerberus is currently maintained under a **benevolent maintainer**
model while the project bootstraps. This document will evolve toward a
maintainer-committee model as the contributor base grows (tracked in
the v1.x backlog).

## Roles

- **Maintainers** — merge access, release authority, final say on
  design disputes. Listed in `CODEOWNERS` (added once the team grows
  beyond the initial maintainer).
- **Contributors** — anyone with a merged PR.

## Decision-making

- Day-to-day changes: lazy consensus among maintainers/reviewers on
  the PR.
- Architecturally significant changes (new external dependency, change
  to a security invariant in §2 of the project plan, breaking change
  to `pkg/cerberus`, new cloud provider support): requires a written
  **RFC** as a PR against `docs/adr/`, open for comment for at least 5
  business days before merge.
- Security-relevant changes: minimum two-maintainer review (see
  `CONTRIBUTING.md`).

## RFC / ADR process

1. Copy `docs/adr/0000-template.md` to
   `docs/adr/NNNN-short-title.md`.
2. Open a PR with status `Proposed`.
3. Once consensus is reached, a maintainer merges it with status
   `Accepted` (or `Rejected`, kept for history).
4. A later ADR may `Supersede` an earlier one — never edit an accepted
   ADR's decision in place.

## Release process

- Releases follow Semantic Versioning (`ROADMAP.md` §Versioning).
- A maintainer tags the release, CI produces signed binaries + SBOM
  (see `docs/development/release-process.md`, added in Sprint 6).
- Security fixes may warrant an out-of-band patch release; see
  `SECURITY.md`.

## Becoming a maintainer

Sustained, high-quality contributions (code, review, triage, docs) over
time are the path to a maintainer invitation. There is no fixed
threshold — it is a judgment call by existing maintainers.
