## Summary

<!-- What does this PR do, and why? -->

## Related issue(s)

<!-- Closes #NNN -->

## Type of change

- [ ] Feature
- [ ] Bug fix
- [ ] Security hardening
- [ ] Documentation
- [ ] Infrastructure / CI

## Checklist

- [ ] Tests added/updated for the change
- [ ] `go build ./...`, `go vet ./...`, `gofmt -l .` are clean
- [ ] `go test -race ./...` passes
- [ ] `CHANGELOG.md` updated (if user-visible)
- [ ] If this touches a security invariant (secret storage, LLM trust
      boundary, remediation separation, SSRF guard, MCP authorization):
      the relevant ADR/threat model doc is updated, and I've flagged
      this PR for 2-reviewer review

## Security-sensitive areas touched (check all that apply)

- [ ] Detector scoring / rule matching
- [ ] Secret fingerprinting / logging paths
- [ ] Web scanner / SSRF guard
- [ ] LLM validator input/output handling
- [ ] MCP authorization
- [ ] Remediation planning/execution
- [ ] IAM / Terraform
- [ ] None of the above
