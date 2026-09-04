# LLM quality gate: baseline measurement and default decision

Tracks issue [#23](https://github.com/HaK0exe/cerberus/issues/23) —
"Measure and document the LLM quality gate (FP/recall with vs.
without)".

## The rule being applied

From [`ROADMAP.md`](../../ROADMAP.md), Sprint 3:

> Quality gate: LLM stays opt-in by default unless it demonstrably
> improves precision without materially hurting recall on the corpus.

This document runs the corpus through the deterministic detection
pipeline with the Sprint 3 LLM review stage off, using the harness in
[`internal/detector/benchmark`](../../internal/detector/benchmark) and
the `cerberus benchmark corpus` command
([`cmd/cerberus/benchmark.go`](../../cmd/cerberus/benchmark.go)).

**Status: partial.** The baseline (no-LLM) numbers below are real,
measured results. The "LLM-assisted" side of the comparison this issue
calls for — the same corpus run with `--llm` against a real
Ollama/llama.cpp server — is **not yet available**; see
["What's missing" below](#whats-missing-and-how-to-complete-it). Per
the quality-gate rule above, the default therefore stays as it already
is: **the LLM stage is opt-in (`--llm`), never on by default**, because
there is no measurement yet that it "demonstrably improves precision
without materially hurting recall" — the gate requires evidence to
turn LLM-on-by-default *on*, not evidence to keep it off, and no such
evidence exists yet.

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

## What's missing, and how to complete it

The issue's acceptance criteria call for the corpus run **with and
without** the LLM stage. This PR delivers the harness and the without
side; the with side needs a real local LLM, which is not available in
this sandbox:

- No Ollama server is running here (`ollama serve` / `:11434`), and no
  model is pulled.
- No llama.cpp server is running either.
- `internal/llm/pipeline`, `internal/llm/ollama`, and
  `internal/llm/llamacpp` are untouched by this PR (out of scope per
  the task boundaries — another line of work owns them) and are ready
  to use as-is.

The harness was deliberately built so this is a one-command follow-up,
**not a rewrite**: `cerberus benchmark corpus` accepts `--llm`
(`cmd/cerberus/benchmark.go`) and wires in the exact same validator
stack `cerberus scan file --llm` uses
(`buildValidator`: Ollama primary → optional llama.cpp fallback →
circuit breaker → response cache, from `internal/llm/pipeline.New`).
`internal/detector/benchmark.Run` takes any `cerberus.Validator`-backed
`detector.Detector` — real or fake — so nothing about the harness
itself needs to change once a real model is available.

To complete the measurement once Ollama is installed:

```bash
# 1. Install/start Ollama and pull the default model this repo targets:
ollama pull llama3.1:8b
ollama serve   # if not already running as a service

# 2. Run the harness against it:
cerberus benchmark corpus --llm --offline=false --verbose

# 3. Compare the printed "LLM-assisted (--llm)" precision/recall/F1
#    against the "baseline (no LLM)" block above, and update this
#    document (and the decision in the "The rule being applied"
#    section) with the real numbers.
```

A note has been left on issue #23
(https://github.com/HaK0exe/cerberus/issues/23) explaining this gap
and what's needed to close it. This PR does not close #23 — the
harness and baseline half of the acceptance criteria are done, but the
"with LLM" comparison the issue explicitly asks for is not, so the
issue should stay open until that follow-up run happens.

## Reproducing this report

```bash
go build -o bin/cerberus ./cmd/cerberus
./bin/cerberus benchmark corpus --verbose
```

The harness's own correctness (precision/recall/F1 math, corpus
loading, confusion-matrix classification) is covered by
`internal/detector/benchmark/benchmark_test.go` against a synthetic,
hand-computed dataset — independent of both the real corpus and any
LLM.
