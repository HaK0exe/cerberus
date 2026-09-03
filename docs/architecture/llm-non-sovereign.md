# LLM non-sovereignty

See [ADR-0002](../adr/0002-llm-non-sovereign.md) for the full decision
record. Summary: the local LLM validator (`cerberus.Validator`,
Sprint 3) can only shift a score within the `llm_review` band
(`[0.70, 0.90)`, see [`scoring.md`](scoring.md)), classify context, or
explain a finding. It never deletes findings, triggers remediation,
holds credentials, reaches the network beyond the local model runtime,
calls tools, or receives a raw secret value.
