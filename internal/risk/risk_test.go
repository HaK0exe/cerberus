package risk

import (
	"testing"
	"time"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func baseCredential(provider string, firstSeen time.Time) cerberus.Credential {
	return cerberus.Credential{
		ID:            "cred_test",
		Provider:      provider,
		Kind:          "test_secret",
		FirstSeen:     firstSeen,
		LastSeen:      firstSeen,
		ExposureCount: 1,
		Status:        cerberus.CredentialStatusActive,
	}
}

func privateFileExposure() cerberus.Exposure {
	return cerberus.Exposure{
		ID:         "exp_1",
		SourceType: cerberus.SourceFile,
		Path:       "a.env",
	}
}

func publicWebExposure() cerberus.Exposure {
	return cerberus.Exposure{
		ID:         "exp_web",
		SourceType: cerberus.SourceWebPage,
		SourceURI:  "https://example.com/leak.js",
	}
}

func TestAssess_LowRiskBaseline(t *testing.T) {
	cred := baseCredential("generic", time.Now())
	assessment := Assess(cred, []cerberus.Exposure{privateFileExposure()})

	if assessment.Level != cerberus.RiskInfo && assessment.Level != cerberus.RiskLow {
		t.Errorf("expected a low baseline risk level, got %s (score %.3f)", assessment.Level, assessment.Score)
	}
}

func TestAssess_PublicExposureScoresHigherThanPrivate(t *testing.T) {
	now := time.Now()
	cred := baseCredential("generic", now)

	private := Assess(cred, []cerberus.Exposure{privateFileExposure()})
	public := Assess(cred, []cerberus.Exposure{publicWebExposure()})

	if public.Score <= private.Score {
		t.Errorf("public exposure should score strictly higher than private: public=%.3f private=%.3f", public.Score, private.Score)
	}
}

func TestAssess_MoreExposuresScoreHigher(t *testing.T) {
	now := time.Now()
	cred := baseCredential("generic", now)

	one := Assess(cred, []cerberus.Exposure{privateFileExposure()})

	var many []cerberus.Exposure
	for i := 0; i < 10; i++ {
		e := privateFileExposure()
		e.ID = privateFileExposure().ID + string(rune('a'+i))
		e.Path = "a" + string(rune('a'+i)) + ".env"
		many = append(many, e)
	}
	manyAssessment := Assess(cred, many)

	if manyAssessment.Score <= one.Score {
		t.Errorf("10 exposures should score strictly higher than 1: many=%.3f one=%.3f", manyAssessment.Score, one.Score)
	}
}

func TestAssess_ExposureFactorIsMonotonic(t *testing.T) {
	now := time.Now()
	cred := baseCredential("generic", now)

	var prevScore float64
	for n := 1; n <= 12; n++ {
		var exposures []cerberus.Exposure
		for i := 0; i < n; i++ {
			e := privateFileExposure()
			e.Path = "file" + string(rune('a'+i)) + ".env"
			exposures = append(exposures, e)
		}
		got := Assess(cred, exposures)
		if n > 1 && got.Score < prevScore {
			t.Errorf("exposure_factor not monotonic at n=%d: score %.3f < previous %.3f", n, got.Score, prevScore)
		}
		prevScore = got.Score
	}
}

func TestAssess_AWSProviderScoresHigherThanGeneric(t *testing.T) {
	now := time.Now()
	exposures := []cerberus.Exposure{privateFileExposure()}

	aws := Assess(baseCredential("aws", now), exposures)
	generic := Assess(baseCredential("generic", now), exposures)

	if aws.Score <= generic.Score {
		t.Errorf("aws provider should score strictly higher than an unclassified provider: aws=%.3f generic=%.3f", aws.Score, generic.Score)
	}
}

func TestAssess_OlderCredentialScoresAtLeastAsHighAsFresh(t *testing.T) {
	exposures := []cerberus.Exposure{privateFileExposure()}

	fresh := Assess(baseCredential("generic", time.Now()), exposures)
	old := Assess(baseCredential("generic", time.Now().Add(-400*24*time.Hour)), exposures)

	if old.Score < fresh.Score {
		t.Errorf("an old credential should never score lower than a fresh one: old=%.3f fresh=%.3f", old.Score, fresh.Score)
	}
	if old.Score == fresh.Score {
		t.Error("expected the 400-day-old credential to score strictly higher than a freshly seen one")
	}
}

func TestAssess_AgeFactorIsNonDecreasing(t *testing.T) {
	now := time.Now()
	ages := []time.Duration{
		1 * time.Hour,
		3 * 24 * time.Hour,
		15 * 24 * time.Hour,
		90 * 24 * time.Hour,
		365 * 24 * time.Hour,
	}

	var prevScore float64
	for i, age := range ages {
		cred := baseCredential("generic", now.Add(-age))
		got := Assess(cred, []cerberus.Exposure{privateFileExposure()})
		if i > 0 && got.Score < prevScore {
			t.Errorf("age_factor not non-decreasing at age=%v: score %.3f < previous %.3f", age, got.Score, prevScore)
		}
		prevScore = got.Score
	}
}

func TestAssess_EveryFactorHasAReason(t *testing.T) {
	cred := baseCredential("aws", time.Now().Add(-200*24*time.Hour))
	exposures := []cerberus.Exposure{privateFileExposure(), publicWebExposure()}

	assessment := Assess(cred, exposures)
	if len(assessment.Factors) == 0 {
		t.Fatal("expected at least one risk factor")
	}
	for _, f := range assessment.Factors {
		if f.Name == "" {
			t.Error("risk factor has empty Name")
		}
		if f.Reason == "" {
			t.Errorf("risk factor %q has empty Reason", f.Name)
		}
		if f.Multiplier < 1.0 {
			t.Errorf("risk factor %q has Multiplier < 1.0 (%.3f): factors must never reduce risk below the floor", f.Name, f.Multiplier)
		}
	}
}

func TestClassify_BoundaryCases(t *testing.T) {
	cases := []struct {
		score float64
		want  cerberus.RiskLevel
	}{
		{1.0, cerberus.RiskInfo},
		{1.49, cerberus.RiskInfo},
		{1.5, cerberus.RiskLow},
		{2.49, cerberus.RiskLow},
		{2.5, cerberus.RiskMedium},
		{3.99, cerberus.RiskMedium},
		{4.0, cerberus.RiskHigh},
		{5.99, cerberus.RiskHigh},
		{6.0, cerberus.RiskCritical},
		{10.0, cerberus.RiskCritical},
	}

	for _, c := range cases {
		if got := classify(c.score); got != c.want {
			t.Errorf("classify(%.2f) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestAssess_ScoreIsBoundedByCeiling(t *testing.T) {
	cred := baseCredential("aws", time.Now().Add(-400*24*time.Hour))
	var exposures []cerberus.Exposure
	for i := 0; i < 20; i++ {
		exposures = append(exposures, publicWebExposure())
	}
	exposures = append(exposures, privateFileExposure())

	assessment := Assess(cred, exposures)
	if assessment.Score > scoreCeiling {
		t.Errorf("Score exceeded documented ceiling: %.3f > %.3f", assessment.Score, scoreCeiling)
	}
}
