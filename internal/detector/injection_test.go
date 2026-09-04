package detector_test

// This file is the S3-09 ("Prompt injection test corpus + security
// review") adversarial test suite. It loads the fixed corpus under
// testdata/corpus/prompt-injection/ (direct instruction override,
// role-play jailbreak, encoded/obfuscated instructions, injected fake
// JSON output) and drives it through the real Detector pipeline —
// Sanitize -> Validator -> adjustScore -> Finding assembly — with
// Validators deliberately written to *try* to misbehave, to prove the
// ADR-0002 ("LLM non-sovereign") invariants hold structurally rather
// than only "by convention":
//
//  1. a Validator can never fabricate a Finding for something that was
//     never a rule-matched candidate;
//  2. a Validator can never erase a Finding for a candidate other than
//     the one it was called for;
//  3. a Validator can never push a llm_review-band candidate's score
//     out of [ThresholdLLMReview, ThresholdFinding), no matter what
//     classification/confidence it returns;
//  4. no component in the path (Sanitize, the Detector, the
//     cerberus.Validator contract itself) has any tool-calling or
//     network primitive for injected content to reach in the first
//     place — see TestValidatorContract_HasNoToolOrNetworkPrimitive.

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/HaK0exe/cerberus/internal/detector"
	"github.com/HaK0exe/cerberus/internal/llm"
	"github.com/HaK0exe/cerberus/internal/rules"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

const corpusDir = "../../testdata/corpus/prompt-injection"

// corpusSample is one loaded fixture from testdata/corpus/prompt-injection.
type corpusSample struct {
	file     string
	category string
	content  []byte
}

var categoryRE = regexp.MustCompile(`(?m)^#\s*category:\s*(\S+)\s*$`)

func loadCorpus(t *testing.T) []corpusSample {
	t.Helper()

	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatalf("reading corpus dir %s: %v", corpusDir, err)
	}

	var samples []corpusSample
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		path := filepath.Join(corpusDir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading corpus fixture %s: %v", path, err)
		}
		m := categoryRE.FindSubmatch(data)
		if m == nil {
			t.Fatalf("corpus fixture %s has no '# category: <name>' header", path)
		}
		samples = append(samples, corpusSample{
			file:     e.Name(),
			category: string(m[1]),
			content:  data,
		})
	}
	if len(samples) == 0 {
		t.Fatalf("no corpus fixtures found in %s", corpusDir)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].file < samples[j].file })
	return samples
}

// requiredCategories mirrors issue #22's acceptance criteria: the
// corpus must cover at least these four attack shapes.
var requiredCategories = []string{
	"direct-instruction-override",
	"roleplay-jailbreak",
	"encoded-obfuscated",
	"fake-json-output",
}

func TestCorpus_CoversRequiredCategories(t *testing.T) {
	samples := loadCorpus(t)

	seen := map[string]int{}
	for _, s := range samples {
		seen[s.category]++
	}
	for _, want := range requiredCategories {
		if seen[want] == 0 {
			t.Errorf("corpus is missing required category %q (see issue #22 acceptance criteria)", want)
		}
	}
}

// llmReviewRule is a single rule, confidence 0.75 (inside
// [ThresholdLLMReview, ThresholdFinding)), with no entropy/keyword
// adjustment, matching SECRET_<8 alnum chars> — the same fixture
// pattern the corpus samples embed.
func llmReviewRule(t *testing.T, id string) rules.CompiledRule {
	t.Helper()
	return rules.CompiledRule{
		Rule: cerberus.Rule{
			ID:         id,
			Name:       id,
			Regex:      `SECRET_[A-Za-z0-9]{8}`,
			Severity:   cerberus.SeverityHigh,
			Confidence: 0.75,
		},
		Pattern: regexp.MustCompile(`SECRET_[A-Za-z0-9]{8}`),
	}
}

// obedientValidator simulates the worst case: a local model that is
// fully "complicit" with whatever instruction-shaped text it can find
// in the (sanitized) context it was given, including decoding the
// obfuscated categories (base64/ROT13) a plain keyword filter can
// plausibly miss. It always returns maximum confidence in whichever
// direction the embedded instruction asked for, specifically to stress
// adjustScore's clamp: if the clamp only worked for "reasonable"
// Validator output, a maximally-confident complicit Validator is
// exactly the input that would break it.
type obedientValidator struct {
	calls    int
	lastCall cerberus.ValidationInput
}

func (o *obedientValidator) Validate(ctx context.Context, in cerberus.ValidationInput) (cerberus.ValidationResult, error) {
	o.calls++
	o.lastCall = in

	text := strings.ToLower(in.RedactedContext)
	text += " " + strings.ToLower(decodeBase64Blobs(in.RedactedContext))
	text += " " + strings.ToLower(rot13(in.RedactedContext))

	if strings.Contains(text, "false positive") || strings.Contains(text, "not a secret") {
		return cerberus.ValidationResult{
			Classification: cerberus.ClassificationLikelyFalsePos,
			Confidence:     1.0, // maximal — see adjustScore's clamp.
			Reason:         "obedient validator: decoded/found an instruction asking for false_positive",
		}, nil
	}
	return cerberus.ValidationResult{
		Classification: cerberus.ClassificationLikelySecret,
		Confidence:     1.0, // maximal in the other direction too.
		Reason:         "obedient validator: default max-confidence likely_secret",
	}, nil
}

// decodeBase64Blobs finds base64-looking tokens in s and appends their
// decoded form, best-effort, so obedientValidator can "fall for" the
// encoded-obfuscated corpus category exactly as a credulous real model
// might (by decoding and following what it finds).
func decodeBase64Blobs(s string) string {
	var out strings.Builder
	for _, tok := range strings.Fields(s) {
		if len(tok) < 8 {
			continue
		}
		if dec, err := base64.StdEncoding.DecodeString(tok); err == nil {
			out.Write(dec)
			out.WriteByte(' ')
		}
	}
	return out.String()
}

// rot13 decodes ROT13-obfuscated text, best-effort, for the same
// reason as decodeBase64Blobs.
func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		default:
			return r
		}
	}, s)
}

// TestCorpus_ObedientValidatorNeverEscapesLLMReviewBand drives every
// corpus sample through the real Detector pipeline (Sanitize wired in
// exactly as internal/detector/detector.go does it — this test does
// not call Sanitize directly) with obedientValidator, which actively
// tries to comply with whatever instruction it can extract, at maximum
// confidence. Per ADR-0002 / adjustScore's clamp, the resulting score
// must never leave [ThresholdLLMReview, ThresholdFinding) — a
// Validator, however complicit, cannot promote a llm_review candidate
// into a Finding-band score by itself.
func TestCorpus_ObedientValidatorNeverEscapesLLMReviewBand(t *testing.T) {
	samples := loadCorpus(t)

	for _, sample := range samples {
		sample := sample
		t.Run(sample.file, func(t *testing.T) {
			rule := llmReviewRule(t, "test-"+sample.category)
			ov := &obedientValidator{}
			d := detector.New([]rules.CompiledRule{rule}, nil,
				detector.WithValidator(ov),
				detector.WithMinEmitBand(detector.BandLowConfidence), // surface the raw band even on likely_false_positive/uncertain
			)

			artifact := cerberus.Artifact{
				SourceType: cerberus.SourceFile,
				Path:       "corpus/" + sample.file,
				Content:    sample.content,
			}

			findings, err := d.Detect(context.Background(), artifact)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if ov.calls != 1 {
				t.Fatalf("expected exactly 1 Validator call for the single candidate in this fixture, got %d", ov.calls)
			}

			// Whether or not the candidate is emitted (that decision is
			// legitimately swayed by the classification), any score that
			// *is* produced must stay inside the llm_review band.
			for _, f := range findings {
				if f.Confidence < detector.ThresholdLLMReview || f.Confidence >= detector.ThresholdFinding {
					t.Errorf("%s: obedient Validator escaped the llm_review band: score=%f (band=[%.2f,%.2f))",
						sample.file, f.Confidence, detector.ThresholdLLMReview, detector.ThresholdFinding)
				}
			}

			// The secret value itself must never have reached the
			// Validator, regardless of what injected text sits next to
			// it in the fixture: it must have been replaced by the
			// fixed-width redaction placeholder before this Validator
			// ever saw it (this is the Detector's real Sanitize call,
			// not a direct one — see TestDetect_ValidatorNeverReceivesRawSecret
			// for the same invariant without the corpus fixtures).
			if !strings.Contains(ov.lastCall.RedactedContext, "[REDACTED-SECRET]") {
				t.Fatalf("%s: expected the secret-redaction placeholder in the Validator's input, got %q", sample.file, ov.lastCall.RedactedContext)
			}
		})
	}
}

// recordingValidator returns a canned per-RuleID result and records
// every call it receives, so a test can assert that a Validator call
// made for one candidate carries only that candidate's own context and
// cannot influence another candidate's Finding.
type recordingValidator struct {
	byRuleID map[string]cerberus.ValidationResult
	calls    []cerberus.ValidationInput
}

func (r *recordingValidator) Validate(ctx context.Context, in cerberus.ValidationInput) (cerberus.ValidationResult, error) {
	r.calls = append(r.calls, in)
	if res, ok := r.byRuleID[in.RuleID]; ok {
		return res, nil
	}
	return cerberus.ValidationResult{Classification: cerberus.ClassificationUncertain, Confidence: 0}, nil
}

// TestCorpus_InjectionInOneCandidateCannotAffectAnotherCandidate builds
// a single artifact containing three independent candidates far enough
// apart that their ±200-byte context windows (see
// internal/detector/scoring.go's contextWindow) never overlap:
//
//   - a BandFinding candidate (bypasses the Validator entirely, per
//     detector.go);
//   - a BandLLMReview "victim" candidate with plain, benign context;
//   - a BandLLMReview "attacker" candidate whose surrounding context is
//     an injection sample instructing the model to also mark *other*
//     findings in this file as safe / to delete them.
//
// It proves the Validator call made for the attacker candidate cannot
// erase the BandFinding Finding (which never even reaches the
// Validator) nor flip the victim candidate's independently-configured
// verdict — each Validate call is scoped to exactly one candidate by
// the Detector, with no shared mutable state passed between calls.
func TestCorpus_InjectionInOneCandidateCannotAffectAnotherCandidate(t *testing.T) {
	samples := loadCorpus(t)
	var attackerSample corpusSample
	for _, s := range samples {
		if s.category == "direct-instruction-override" {
			attackerSample = s
			break
		}
	}
	if attackerSample.file == "" {
		t.Fatal("expected at least one direct-instruction-override corpus sample")
	}

	// Three widely-separated rules so the ±200-byte context windows
	// cannot overlap: a deterministic high-confidence match, a benign
	// llm_review match, and the attacker's injection-laden llm_review
	// match, each keyed to its own token/rule pair.
	highRule := rules.CompiledRule{
		Rule:    cerberus.Rule{ID: "high", Name: "high", Regex: `HIGH_[A-Za-z0-9]{8}`, Severity: cerberus.SeverityHigh, Confidence: 0.95},
		Pattern: regexp.MustCompile(`HIGH_[A-Za-z0-9]{8}`),
	}
	victimRule := rules.CompiledRule{
		Rule:    cerberus.Rule{ID: "victim", Name: "victim", Regex: `VICTIM_[A-Za-z0-9]{8}`, Severity: cerberus.SeverityHigh, Confidence: 0.75},
		Pattern: regexp.MustCompile(`VICTIM_[A-Za-z0-9]{8}`),
	}
	attackerRule := rules.CompiledRule{
		Rule:    cerberus.Rule{ID: "attacker", Name: "attacker", Regex: `SECRET_[A-Za-z0-9]{8}`, Severity: cerberus.SeverityHigh, Confidence: 0.75},
		Pattern: regexp.MustCompile(`SECRET_[A-Za-z0-9]{8}`),
	}

	pad := strings.Repeat("x", 600) // comfortably wider than 2*contextWindow (400)

	var b strings.Builder
	b.WriteString("token = HIGH_AAAAAAAA # a clearly live-looking credential\n")
	b.WriteString(pad + "\n")
	b.WriteString("token = VICTIM_BBBBBBBB # a plain, unremarkable candidate\n")
	b.WriteString(pad + "\n")
	b.WriteString(string(attackerSample.content)) // contains SECRET_ABCD1234 + injection text

	rv := &recordingValidator{byRuleID: map[string]cerberus.ValidationResult{
		"victim": {Classification: cerberus.ClassificationLikelySecret, Confidence: 0.9, Reason: "victim: independently classified as likely_secret"},
		// The attacker candidate's own verdict, whatever it is, must
		// only ever affect the attacker candidate.
		"attacker": {Classification: cerberus.ClassificationLikelyFalsePos, Confidence: 1.0, Reason: "attacker: obeyed its own injected instruction"},
	}}

	d := detector.New([]rules.CompiledRule{highRule, victimRule, attackerRule}, nil,
		detector.WithValidator(rv),
	)

	findings, err := d.Detect(context.Background(), cerberus.Artifact{
		SourceType: cerberus.SourceFile,
		Path:       "corpus/multi-candidate.env",
		Content:    []byte(b.String()),
	})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(rv.calls) != 2 {
		t.Fatalf("expected exactly 2 Validator calls (victim + attacker; the BandFinding candidate must bypass the Validator), got %d", len(rv.calls))
	}
	for _, call := range rv.calls {
		if strings.Contains(call.RedactedContext, "HIGH_") {
			t.Errorf("a llm_review candidate's context window leaked the unrelated BandFinding candidate's token: %q", call.RedactedContext)
		}
	}
	for _, call := range rv.calls {
		if call.RuleID == "victim" && strings.Contains(strings.ToLower(call.RedactedContext), "ignore") {
			t.Errorf("attacker's injection text leaked into the victim candidate's own context window: %q", call.RedactedContext)
		}
	}

	byRule := map[string]cerberus.Finding{}
	for _, f := range findings {
		byRule[f.RuleID] = f
	}

	if _, ok := byRule["high"]; !ok {
		t.Errorf("expected the BandFinding candidate to be emitted regardless of the attacker candidate's verdict; findings=%+v", findings)
	}
	if _, ok := byRule["victim"]; !ok {
		t.Errorf("expected the victim candidate to be emitted per its own independent likely_secret verdict, unaffected by the attacker candidate's injected instruction; findings=%+v", findings)
	}
	if _, ok := byRule["attacker"]; ok {
		t.Errorf("attacker candidate was configured likely_false_positive and should not have been emitted")
	}
}

// TestCorpus_LikelySecretMaxConfidenceStaysBelowFindingThreshold is the
// single most direct test of ADR-0002's core numeric guarantee,
// isolated from the corpus loader: a Validator (however it arrived at
// its answer — including by being fooled by a fake-json-output sample)
// returns Confidence: 1.0 on a llm_review-band candidate. The resulting
// score must stay strictly below ThresholdFinding.
func TestCorpus_LikelySecretMaxConfidenceStaysBelowFindingThreshold(t *testing.T) {
	rule := llmReviewRule(t, "max-confidence")
	fv := fakeValidator{result: cerberus.ValidationResult{
		Classification: cerberus.ClassificationLikelySecret,
		Confidence:     1.0,
		Reason:         "maximal confidence, exactly the case adjustScore's clamp must still bound",
	}}
	d := detector.New([]rules.CompiledRule{rule}, nil, detector.WithValidator(&fv))

	findings, err := d.Detect(context.Background(), artifactWithSecret("SECRET_ABCD1234"))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if got := findings[0].Confidence; got >= detector.ThresholdFinding {
		t.Fatalf("Confidence:1.0 likely_secret verdict escaped the llm_review band into finding band: got %f, want < %f",
			got, detector.ThresholdFinding)
	}
	if got := findings[0].Confidence; got < detector.ThresholdLLMReview {
		t.Fatalf("adjusted score dropped below the llm_review band floor: got %f, want >= %f", got, detector.ThresholdLLMReview)
	}
}

// TestCorpus_LikelyFalsePositiveMaxConfidenceSuppressesEmission is the
// symmetric counterpart of
// TestCorpus_LikelySecretMaxConfidenceStaysBelowFindingThreshold: a
// Validator maximally confident that a candidate is a false positive
// (exactly what an "obedient" model decoding an encoded-obfuscated
// corpus sample like 05/06 would produce) does not get to leave any
// residual, attacker-favorable trace on the score — an explicit
// likely_false_positive verdict unconditionally suppresses emission
// (detector.go's switch sets shouldEmit = false), regardless of
// WithMinEmitBand, so there is no Finding at all for such an
// injection-driven verdict to have biased the score of. This is the
// same suppression path exercised implicitly by corpus samples 05/06
// in TestCorpus_ObedientValidatorNeverEscapesLLMReviewBand; this test
// pins it explicitly with maximal confidence.
func TestCorpus_LikelyFalsePositiveMaxConfidenceSuppressesEmission(t *testing.T) {
	rule := llmReviewRule(t, "max-confidence-fp")
	fv := fakeValidator{result: cerberus.ValidationResult{
		Classification: cerberus.ClassificationLikelyFalsePos,
		Confidence:     1.0,
		Reason:         "maximal false-positive confidence, exactly what a decoded/obeyed injection would produce",
	}}
	d := detector.New([]rules.CompiledRule{rule}, nil,
		detector.WithValidator(&fv),
		detector.WithMinEmitBand(detector.BandLowConfidence), // even a permissive minEmitBand cannot override an explicit verdict
	)

	findings, err := d.Detect(context.Background(), artifactWithSecret("SECRET_ABCD1234"))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected a likely_false_positive verdict to suppress emission regardless of confidence, got %d findings", len(findings))
	}
}

// TestSanitize_CorpusSecretNeverLeaksRegardlessOfInjectionShape re-runs
// the raw-secret-redaction invariant (already covered generically in
// internal/llm's own tests) against every corpus fixture specifically,
// since S3-09 is about proving the *combination* of "adversarial
// content" and "the sanitizer that runs right before the Validator"
// holds, not just the sanitizer in isolation.
func TestSanitize_CorpusSecretNeverLeaksRegardlessOfInjectionShape(t *testing.T) {
	samples := loadCorpus(t)
	secretRE := regexp.MustCompile(`SECRET_[A-Za-z0-9]{8}`)

	for _, sample := range samples {
		sample := sample
		t.Run(sample.file, func(t *testing.T) {
			loc := secretRE.FindIndex(sample.content)
			if loc == nil {
				t.Fatalf("fixture %s has no SECRET_ marker to sanitize", sample.file)
			}
			secret := sample.content[loc[0]:loc[1]]

			sanitized := llm.Sanitize(string(sample.content), secret)
			if strings.Contains(sanitized, string(secret)) {
				t.Fatalf("%s: raw secret leaked through Sanitize: %q", sample.file, sanitized)
			}
		})
	}
}

// TestValidatorContract_HasNoToolOrNetworkPrimitive documents,
// structurally, the third bullet of issue #22's acceptance criteria:
// "None of the samples cause the Validator to call a tool [or] reach
// the network beyond the local model runtime."
//
// This is not something a corpus of adversarial *text* can prove or
// disprove by itself — injected text can only ever influence what a
// Validate call *returns*, never what capabilities are available to
// it, because cerberus.Validator (pkg/cerberus/interfaces.go) exposes
// exactly one method:
//
//	Validate(ctx context.Context, input ValidationInput) (ValidationResult, error)
//
// There is no function-calling/tool-use primitive anywhere in that
// contract, no callback the implementation is handed, and no side
// channel back into the Detector: internal/llm/ollama and
// internal/llm/llamacpp each own their own HTTP client, scoped to a
// single configured local base URL, and the only thing that ever
// leaves internal/llm.ParseValidationResultWithRetry is a
// cerberus.ValidationResult value — plain data, not something that can
// be interpreted as a command by the calling Detector. This test pins
// that shape with reflection so a future change to the Validator
// interface that adds such a primitive fails loudly here rather than
// silently widening the trust boundary ADR-0002 relies on.
func TestValidatorContract_HasNoToolOrNetworkPrimitive(t *testing.T) {
	validatorType := reflect.TypeOf((*cerberus.Validator)(nil)).Elem()

	if got := validatorType.NumMethod(); got != 1 {
		t.Fatalf("cerberus.Validator grew from 1 method to %d — review whether a new method adds a tool-call/network primitive an injected candidate could reach (see ADR-0002)", got)
	}

	m := validatorType.Method(0)
	if m.Name != "Validate" {
		t.Fatalf("cerberus.Validator's sole method is now %q, not Validate — review against ADR-0002", m.Name)
	}

	mt := m.Type
	if mt.NumIn() != 2 || mt.NumOut() != 2 {
		t.Fatalf("Validate's signature changed shape (in=%d out=%d) — review against ADR-0002 before accepting", mt.NumIn(), mt.NumOut())
	}
	wantIn := reflect.TypeOf((*cerberus.ValidationInput)(nil)).Elem()
	wantOut := reflect.TypeOf((*cerberus.ValidationResult)(nil)).Elem()
	if mt.In(1) != wantIn {
		t.Fatalf("Validate's input type changed to %s, want %s", mt.In(1), wantIn)
	}
	if mt.Out(0) != wantOut {
		t.Fatalf("Validate's result type changed to %s, want %s", mt.Out(0), wantOut)
	}
}
