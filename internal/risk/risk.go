// Package risk implements the risk engine: a deterministic, explainable
// mapping from a Credential and its Exposures to a RiskAssessment. It
// is deliberately separate from internal/detector's confidence scoring
// — detection confidence answers "how sure are we this is a secret?",
// risk answers "how bad is it that this secret is exposed, right now?"
// See docs/adr/0005-risk-engine.md.
package risk

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// Risk-level score thresholds. Every factor in Assess is built to
// never produce a Multiplier below 1.0 (a factor may leave the score
// unchanged, never reduce it — an assessment only ever escalates risk
// on top of the credential-confidence floor), so Score always lands in
// [1.0, scoreCeiling]. These cutoffs are starting points to be
// calibrated the same way internal/detector's ThresholdIgnore/
// ThresholdLLMReview/ThresholdFinding are: against real triage
// outcomes once they exist, not treated as fixed forever.
const (
	thresholdLow      = 1.5
	thresholdMedium   = 2.5
	thresholdHigh     = 4.0
	thresholdCritical = 6.0

	// scoreCeiling bounds the product of all factors before mapping to
	// a RiskLevel, so one pathological combination of factors can't
	// produce an unbounded, uninterpretable number. At today's factor
	// maxima (exposure 2.5 × visibility 1.6 × provider 1.5 × age 1.6 ×
	// reuse 1.8 ≈ 17.3) this ceiling is reachable; when it clamps, that
	// is itself informative ("this is at least as bad as CRITICAL gets
	// modeled today") rather than a sign the formula is wrong.
	scoreCeiling = 10.0
)

// Assess computes an explainable RiskAssessment for cred from its
// Exposures. It is pure and deterministic: the same (Credential,
// []Exposure) pair always produces the same RiskAssessment, and it
// never mutates its inputs or reaches the network.
//
// RiskScore = credential_confidence × exposure_factor × visibility_factor
//
//	× provider_factor × age_factor × reuse_factor
//
// A privilege_factor (e.g. "this AWS key has iam:*") is intentionally
// absent: there is no credential-intelligence adapter yet that could
// honestly populate it (see docs/adr/0005-risk-engine.md, deferred).
func Assess(cred cerberus.Credential, exposures []cerberus.Exposure) cerberus.RiskAssessment {
	now := time.Now()

	factors := []cerberus.RiskFactor{
		credentialConfidenceFactor(cred),
		exposureFactor(cred, exposures),
		visibilityFactor(exposures),
		providerFactor(cred),
		ageFactor(cred, now),
		reuseFactor(exposures),
	}

	product := 1.0
	for _, f := range factors {
		product *= f.Multiplier
	}
	score := math.Min(product, scoreCeiling)

	return cerberus.RiskAssessment{
		Score:   score,
		Level:   classify(score),
		Factors: factors,
	}
}

// classify maps a bounded Score to a RiskLevel using the package's
// documented thresholds. Every factor has a floor of 1.0, so INFO is
// reachable and is not a degenerate/unused level.
func classify(score float64) cerberus.RiskLevel {
	switch {
	case score >= thresholdCritical:
		return cerberus.RiskCritical
	case score >= thresholdHigh:
		return cerberus.RiskHigh
	case score >= thresholdMedium:
		return cerberus.RiskMedium
	case score >= thresholdLow:
		return cerberus.RiskLow
	default:
		return cerberus.RiskInfo
	}
}

// credentialConfidenceFactor is honestly a placeholder floor today: a
// Credential does not currently retain the detection Confidence of the
// Finding(s) it was correlated from (see internal/credentials.Correlate
// — it keeps timestamps and identity, not scores). Rather than fabricate
// a number, this factor stays at the neutral 1.0 floor and says so; once
// Credential/Correlate carries a representative Finding.Confidence (a
// natural follow-up — see the ADR), this should scale down for
// low-confidence, likely-false-positive credentials instead of treating
// every correlated Credential as equally certain.
func credentialConfidenceFactor(cred cerberus.Credential) cerberus.RiskFactor {
	return cerberus.RiskFactor{
		Name:       "credential_confidence",
		Multiplier: 1.0,
		Reason:     "placeholder floor: Credential does not yet retain the originating Finding's Confidence, so this factor cannot honestly move the score — see docs/adr/0005-risk-engine.md",
	}
}

// exposureFactor scales with how many distinct locations the credential
// was found in: more places it needs to be rotated/tracked down from is
// strictly worse, but each additional location matters less than the
// last (going from 1 to 2 locations is a bigger jump in real risk than
// 10 to 11), so the bonus is capped rather than linear.
func exposureFactor(cred cerberus.Credential, exposures []cerberus.Exposure) cerberus.RiskFactor {
	n := len(exposures)
	if n == 0 {
		n = cred.ExposureCount
	}
	if n < 1 {
		n = 1
	}

	extra := n - 1
	if extra > 10 {
		extra = 10
	}
	multiplier := 1.0 + 0.15*float64(extra)

	return cerberus.RiskFactor{
		Name:       "exposure_factor",
		Multiplier: multiplier,
		Reason:     formatExposureReason(n, extra),
	}
}

func formatExposureReason(n, extra int) string {
	if n <= 1 {
		return "found in a single location: no reuse bonus"
	}
	suffix := ""
	if extra >= 10 {
		suffix = " (capped at 10 extra locations)"
	}
	return "found in " + strconv.Itoa(n) + " distinct locations: +0.15 per extra location beyond the first" + suffix
}

// visibilityFactor takes the worst case across every Exposure: a
// credential is exactly as exposed as its most reachable location,
// regardless of how many other, more contained locations it also
// appears in.
func visibilityFactor(exposures []cerberus.Exposure) cerberus.RiskFactor {
	const (
		levelPublic  = 1.6
		levelUnknown = 1.2
		levelPrivate = 1.0
	)

	worst := levelUnknown // no exposures at all: treat as unknown reachability, not as safely private
	worstReason := "no exposure locations available: reachability unknown"
	if len(exposures) > 0 {
		worst = 0
	}

	for _, e := range exposures {
		level := levelUnknown
		reason := "location " + locationLabel(e) + " has no visibility information: treated as unknown reachability"

		switch {
		case strings.EqualFold(e.Visibility, "public"):
			level = levelPublic
			reason = "location " + locationLabel(e) + " is explicitly marked public"
		case e.SourceType == cerberus.SourceWebPage || e.SourceType == cerberus.SourceWebScript:
			level = levelPublic
			reason = "location " + locationLabel(e) + " is a web-sourced exposure (" + string(e.SourceType) + "): treated as publicly reachable"
		case strings.EqualFold(e.Visibility, "private"):
			level = levelPrivate
			reason = "location " + locationLabel(e) + " is explicitly marked private"
		case e.SourceType == cerberus.SourceGitWorkingTree || e.SourceType == cerberus.SourceFile:
			level = levelPrivate
			reason = "location " + locationLabel(e) + " is a local file/working-tree exposure: treated as private"
		}

		if level > worst {
			worst = level
			worstReason = reason
		}
	}

	return cerberus.RiskFactor{
		Name:       "visibility_factor",
		Multiplier: worst,
		Reason:     "worst-case across all exposures: " + worstReason,
	}
}

func locationLabel(e cerberus.Exposure) string {
	if e.Path != "" {
		return e.Path
	}
	if e.SourceURI != "" {
		return e.SourceURI
	}
	return string(e.SourceType)
}

// providerFactor is a small, deliberately coarse lookup reflecting
// blast radius: a leaked cloud IAM credential can typically reach far
// more than a leaked SCM personal-access-token, which in turn typically
// reaches more than an unclassified generic secret. This is a starting
// heuristic (see docs/adr/0005-risk-engine.md), not a substitute for the
// real answer — actually enumerating what the credential can do — which
// belongs to a future credential-intelligence enricher, not this engine.
func providerFactor(cred cerberus.Credential) cerberus.RiskFactor {
	provider := strings.ToLower(cred.Provider)

	multiplier := 1.0
	tier := "default/unclassified provider"
	switch provider {
	case "aws", "gcp", "azure":
		multiplier = 1.5
		tier = "cloud IAM provider"
	case "github", "gitlab", "stripe":
		multiplier = 1.2
		tier = "SCM/payment provider"
	}

	return cerberus.RiskFactor{
		Name:       "provider_factor",
		Multiplier: multiplier,
		Reason:     "provider " + describeProvider(cred.Provider) + " classified as " + tier,
	}
}

func describeProvider(provider string) string {
	if provider == "" {
		return "<unknown>"
	}
	return "\"" + provider + "\""
}

// ageFactor treats an old, still-active exposure as worse than a fresh
// one: the longer a secret has sat exposed, the more likely it has
// already been scraped/cached/reused by something other than Cerberus,
// and the more suspicious it is that nobody has rotated it yet.
func ageFactor(cred cerberus.Credential, now time.Time) cerberus.RiskFactor {
	if cred.FirstSeen.IsZero() {
		return cerberus.RiskFactor{
			Name:       "age_factor",
			Multiplier: 1.0,
			Reason:     "no FirstSeen recorded: treated as freshly observed",
		}
	}

	age := now.Sub(cred.FirstSeen)

	var multiplier float64
	var bucket string
	switch {
	case age < 24*time.Hour:
		multiplier, bucket = 1.0, "under 24h old"
	case age < 7*24*time.Hour:
		multiplier, bucket = 1.1, "under 7 days old"
	case age < 30*24*time.Hour:
		multiplier, bucket = 1.25, "under 30 days old"
	case age < 180*24*time.Hour:
		multiplier, bucket = 1.4, "under 180 days old"
	default:
		multiplier, bucket = 1.6, "180 days old or more"
	}

	return cerberus.RiskFactor{
		Name:       "age_factor",
		Multiplier: multiplier,
		Reason:     "first observed " + formatAge(age) + " ago (" + bucket + ") with no evidence of rotation",
	}
}

func formatAge(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days < 1 {
		return "less than a day"
	}
	return strconv.Itoa(days) + " day(s)"
}

// reuseFactor counts distinct SourceTypes across a credential's
// exposures. The same secret checked into three commits of one repo is
// one kind of reuse; the same secret also showing up in a public web
// bundle is reuse across an unrelated surface, which is strictly worse
// — this is a coarse proxy for that distinction until a real
// cross-surface correlation signal exists.
func reuseFactor(exposures []cerberus.Exposure) cerberus.RiskFactor {
	distinct := map[cerberus.SourceType]bool{}
	for _, e := range exposures {
		distinct[e.SourceType] = true
	}

	n := len(distinct)
	if n < 1 {
		n = 1
	}
	extra := n - 1
	if extra > 4 {
		extra = 4
	}
	multiplier := 1.0 + 0.2*float64(extra)

	reason := "all exposures share a single source type: no cross-surface reuse"
	if n > 1 {
		reason = "exposures span " + strconv.Itoa(n) + " distinct source types: reuse across unrelated surfaces"
	}

	return cerberus.RiskFactor{
		Name:       "reuse_factor",
		Multiplier: multiplier,
		Reason:     reason,
	}
}
