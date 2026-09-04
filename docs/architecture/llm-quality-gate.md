# LLM quality gate: baseline measurement and default decision

Tracks issue [#23](https://github.com/HaK0exe/cerberus/issues/23) —
"Measure and document the LLM quality gate (FP/recall with vs.
without)".

## The rule being applied

From [`ROADMAP.md`](../../ROADMAP.md), Sprint 3:

> Quality gate: LLM stays opt-in by default unless it demonstrably
> improves precision without materially hurting recall on the corpus.

This document runs the corpus through the deterministic detection
pipeline with the Sprint 3 LLM review stage off and on, using the
harness in [`internal/detector/benchmark`](../../internal/detector/benchmark)
and the `cerberus benchmark corpus` command
([`cmd/cerberus/benchmark.go`](../../cmd/cerberus/benchmark.go)).

**Status: complete.** Both sides of the comparison below are real,
measured results — baseline (no LLM) and LLM-assisted (`--llm` against
a real local Ollama server, model `gemma3:4b`). Applying the
quality-gate rule above to these numbers: **the LLM stage stays
opt-in (`--llm`), not on by default.** Recall improved substantially
(+0.333) and F1 improved (+0.203), but precision *decreased*
(1.0000 → 0.9091 — one new false positive) rather than improving as
the rule requires, and the corpus is only 22 samples, too small for a
single false positive's ±10-point precision swing to be a reliable
signal either way. See ["LLM-assisted measurement"](#llm-assisted-measurement-real-result)
below for the full reasoning, and
["Re-running this benchmark"](#re-running-this-benchmark) to reproduce
or re-evaluate once the corpus is larger (#66/#13).

## The corpus

`testdata/corpus/` (added in this PR) is a **starter corpus**: 22
labeled samples (12 `true_positive/`, 10 `false_positive/`), not the
5,000 true-positive / 10,000 false-positive target size described in
[`docs/development/corpus.md`](../development/corpus.md). Building the
corpus out to that target size is tracked separately in issue
[#66](https://github.com/HaK0exe/cerberus/issues/66) ("Build corpus to
target size and publish precision/recall benchmark") and issue
[#13](https://github.com/HaK0exe/cerberus/issues/13) (Git-history/web
fixtures) — out of scope here. **The numbers below should be read as a
proof that the harness and its metrics are correct, not as a
statistically robust precision/recall figure** — 23 samples is too
small for that. Re-run `cerberus benchmark corpus` once the larger
corpus lands to get a number worth trusting operationally.

The starter corpus was built by hand to exercise every shipped rule
(`rules/cloud/aws.yaml`, `rules/generic/passwords.yaml`,
`rules/generic/tokens.yaml`, `rules/payment/stripe.yaml`,
`rules/private-keys/pem.yaml`, `rules/scm/github.yaml`) across all four
scoring bands (`finding`, `llm_review`, `low_confidence`, `ignore` —
see [`scoring.md`](scoring.md)), with particular attention to the
`llm_review` band ([0.70, 0.90)), since that's the only band the LLM
stage ever touches. All true-positive samples use synthetic,
never-issued credential formats — no real secret is committed, per
`docs/development/corpus.md`'s rule.

One planned sample — a synthetic `stripe-secret-key-live` true
positive — was dropped after GitHub's push protection blocked the
push, flagging it as a real Stripe live secret key even though it was
a hand-typed, never-issued value: `stripe-secret-key-live`'s rule
regex (`sk_live_[A-Za-z0-9]{24,247}`) is essentially the same shape
GitHub's own Stripe scanner matches on, so any string satisfying our
rule also satisfies theirs. That's arguably a useful signal that the
rule is realistic; it does mean the `stripe-secret-key-live` rule has
no true-positive corpus coverage yet (`stripe-secret-key-test` is
covered, and exercises the identical scoring path). Left as a gap for
whoever expands the corpus under #66/#13.

## Baseline (no LLM) — real measurement

```text
$ cerberus benchmark corpus
corpus:   22 samples (testdata/corpus)

baseline (no LLM)
  precision: 1.0000
  recall:    0.5000
  F1:        0.6667
  confusion: tp=6 fn=6 fp=0 tn=10 (n=22)
```

This is the actual output of `cerberus benchmark corpus` against the
committed corpus, using a `detector.Detector` built exactly the way
`internal/detector.New` defaults it (no `WithValidator`, default
`WithMinEmitBand` — i.e. only the `finding` band, score ≥ 0.90, is ever
emitted). It is deterministic and reproducible: no network call, no
LLM, no randomness in scoring.

Per-sample breakdown (`cerberus benchmark corpus --verbose`):

- **6 true positives**: every sample designed to land in the
  `finding` band (AWS access key, AWS secret key, GitHub PAT
  classic/fine-grained, Stripe test key, PEM private key block) was
  correctly flagged.
- **0 false positives**: every false-positive sample was correctly
  left unflagged — none of them reach the `finding` band by
  construction.
- **6 false negatives**, all real secrets the deterministic stage
  alone cannot recover:
  - 4 samples deliberately land in the `llm_review` band ([0.70,
    0.90)) — a realistic JWT and API-key/token assignment in a
    plausible (non-"example"/"placeholder") context. Without the LLM
    stage these are correctly identified as *ambiguous* by the
    deterministic scorer but dropped rather than emitted, since
    `llm_review` never reaches `finding` on its own — this is exactly
    the band the LLM stage exists to adjudicate.
  - 2 samples (`generic-password-assignment`) land in `low_confidence`
    (score 0.50) — this rule's own confidence/keyword weights cap out
    at 0.50 (base 0.4 + 0.10 keyword bonus, entropy disabled), so it
    can never reach `llm_review` (≥ 0.70) or `finding` under the
    current scoring weights, regardless of the LLM stage. This is a
    scoring-tuning gap, not something Sprint 3's LLM stage is scoped
    to fix — noted here for whoever picks up rule/scoring calibration
    next (see [`scoring.md`](scoring.md)'s note that thresholds are
    starting points, not fixed constants).

## LLM-assisted measurement (real result)

```text
$ cerberus benchmark corpus --llm --offline=false --llm-model gemma3:4b --verbose
LLM-assisted (--llm)
  precision: 0.9091
  recall:    0.8333
  F1:        0.8696
  confusion: tp=10 fn=2 fp=1 tn=9 (n=22)
```

Measured against a real local Ollama server (`ollama serve`,
`http://localhost:11434`) running `gemma3:4b` — not the CLI's own
default model (`llama3.1:8b`, which was not the model available on the
machine this was measured on; pass `--llm-model` to match whatever is
actually pulled). No fake/simulated Validator is used anywhere in this
harness — `--llm` always wires in the real `internal/llm/pipeline`
stack (Ollama → optional llama.cpp fallback → circuit breaker →
response cache), so these numbers reflect an actual model call for
every `llm_review`-band candidate.

**What changed vs. baseline:**

- **4 of the 6 baseline false negatives in the `llm_review` band
  became true positives** — the two `generic-api-key-assignment` and
  two `generic-jwt` samples the deterministic stage correctly flagged
  as *ambiguous* (score in `[0.70, 0.90)`) were classified
  `likely_secret` by the model and promoted, exactly the behavior the
  LLM stage exists for.
- **The 2 `generic-password-assignment` false negatives remain false
  negatives** — as predicted in the baseline section above, those
  samples score `0.50` (`low_confidence`) under the current rule
  weights and never reach the `llm_review` band, so the LLM stage
  never even sees them. This is the same pre-existing scoring-tuning
  gap, unaffected by the LLM stage either way.
- **One new false positive**:
  `false_positive/generic-api-key-assignment_fp_config-sample.yaml` —
  a sample-config YAML file (`token: "k7Lp0Vb3Nc6Ht9Ws1Fg4Ae8Dj2Rk5YQx"`,
  clearly a copy-this-and-edit template by its own comment) that the
  model classified `likely_secret`. This is a defensible mistake — the
  token value alone is indistinguishable from a real one, and only the
  surrounding "local dev only, copy to config.yaml" comment marks it
  as a template, which is exactly the kind of contextual judgment call
  an LLM stage is *supposed* to help with, not always get right. It's
  a genuine miss, not a sign of the sanitizer or schema-validation
  layers misbehaving (`internal/llm.ParseValidationResultWithRetry`
  parsed a well-formed, schema-valid response; the model was simply
  wrong).

**Applying the quality-gate rule:** recall improved substantially
(0.5000 → 0.8333, +0.333) and F1 improved (0.6667 → 0.8696, +0.203),
but precision *decreased* (1.0000 → 0.9091) rather than improving as
the rule requires ("demonstrably improves precision without
materially hurting recall") — the actual trade observed here is the
mirror image: recall improves a lot, precision drops a little. On a
22-sample corpus, a single false positive is a 10-percentage-point
swing on the false-positive-bearing subset, which is not a reliable
basis for concluding precision genuinely regresses at scale, but it's
equally not a basis for concluding it doesn't. **Decision: the LLM
stage stays opt-in (`--llm`), not enabled by default.** The signal is
promising — recall and F1 both improve meaningfully — but the letter
of the quality gate asks for a precision improvement specifically, and
this measurement doesn't show one; re-run this benchmark once the
corpus reaches the target size in #66/#13 before revisiting the
default.

## Re-running this benchmark

```bash
go build -o bin/cerberus ./cmd/cerberus

# Baseline (no LLM, no network call):
./bin/cerberus benchmark corpus --verbose

# LLM-assisted (requires a running Ollama server and a pulled model):
ollama pull <model>            # e.g. llama3.1:8b, or whatever's available
ollama serve                   # if not already running
./bin/cerberus benchmark corpus --llm --offline=false --llm-model <model> --verbose
```

The harness's own correctness (precision/recall/F1 math, corpus
loading, confusion-matrix classification) is covered by
`internal/detector/benchmark/benchmark_test.go` against a synthetic,
hand-computed dataset — independent of both the real corpus and any
LLM.
