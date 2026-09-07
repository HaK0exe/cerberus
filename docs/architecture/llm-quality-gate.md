# Detection and LLM quality gate

The committed corpus is the release-facing regression suite for the
detection pipeline. Run it with:

```bash
cerberus benchmark corpus
```

## Current deterministic measurement

Measured on the 202-file corpus committed with this revision:

```text
strict baseline (finding band only, no LLM)
  precision: 1.0000
  recall:    0.1389
  F1:        0.2439
  confusion: tp=10 fn=62 fp=0 tn=130 (n=202)

shipping CLI baseline (low-confidence and above, no LLM)
  precision: 0.9077
  recall:    0.8194
  F1:        0.8613
  confusion: tp=59 fn=13 fp=6 tn=124 (n=202)
```

These are intentionally separate measurements. The strict detector
baseline emits only scores at or above the `finding` threshold and is
the correct baseline for deciding whether LLM review improves the
ambiguous band. The CLI emits the `low_confidence` band as well so a
human or CI policy can make the final severity decision. Reporting
only the strict number would therefore understate the behavior users
receive from `scan file`, `git scan`, and `web scan`.

`internal/detector/benchmark/corpus_quality_test.go` enforces a release
floor of 0.90 precision and 0.80 recall for the shipping CLI policy.
Changing rules, scoring, or thresholds must keep that test green or
update the threshold with explicit calibration evidence.

## LLM decision

The LLM stage remains opt-in. It is allowed to review only the
`llm_review` band and cannot remove a finding or promote a score beyond
that band's structural bounds.

The earlier Ollama measurement used a 22-file starter corpus and is no
longer comparable to the current 202-file corpus. Before changing the
default, rerun the real pipeline against the complete corpus:

```bash
cerberus benchmark corpus \
  --llm --offline=false \
  --llm-model <locally-installed-model> \
  --verbose
```

Enabling LLM review by default requires evidence that it improves
precision without materially reducing recall. Model name, digest,
prompt version, ruleset version, corpus commit, and full confusion
matrix must be recorded with the result.

## Corpus scope

The current corpus has 72 synthetic true-positive files and 130
realistic false-positive files, including Git history, JavaScript,
source map, documentation, and configuration contexts. It is still
smaller than the long-term 5,000/10,000 target in
`docs/development/corpus.md`; the current metrics are a regression
gate, not a claim of population-level accuracy.
