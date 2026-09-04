package benchmark

// Confusion is a binary confusion matrix over corpus samples, at
// per-sample (not per-Finding) granularity: a sample counts as a
// "positive" detector outcome if the detector emitted one or more
// Findings for it, regardless of how many.
type Confusion struct {
	TruePositives  int // TruePositive sample, detector emitted >=1 Finding
	FalseNegatives int // TruePositive sample, detector emitted 0 Findings (missed)
	FalsePositives int // FalsePositive sample, detector emitted >=1 Finding (wrongly flagged)
	TrueNegatives  int // FalsePositive sample, detector emitted 0 Findings (correctly ignored)
}

// Total is the number of samples the matrix was computed over.
func (c Confusion) Total() int {
	return c.TruePositives + c.FalseNegatives + c.FalsePositives + c.TrueNegatives
}

// Metrics is the standard precision/recall/F1 derived from a
// Confusion matrix, plus the matrix itself for transparency.
type Metrics struct {
	Confusion Confusion
	Precision float64
	Recall    float64
	F1        float64
}

// Compute derives Metrics from a Confusion matrix.
//
//   - Precision = TP / (TP + FP): of everything flagged, how much was
//     a real secret. Undefined (reported as 0) when nothing was
//     flagged at all.
//   - Recall = TP / (TP + FN): of every real secret in the corpus, how
//     much was flagged. Undefined (reported as 0) when the corpus has
//     no true-positive samples.
//   - F1 = 2 * Precision * Recall / (Precision + Recall), the harmonic
//     mean. 0 when both are 0.
func Compute(c Confusion) Metrics {
	m := Metrics{Confusion: c}

	if flagged := c.TruePositives + c.FalsePositives; flagged > 0 {
		m.Precision = float64(c.TruePositives) / float64(flagged)
	}
	if actual := c.TruePositives + c.FalseNegatives; actual > 0 {
		m.Recall = float64(c.TruePositives) / float64(actual)
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}

	return m
}
