package detector

import "math"

// ShannonEntropy returns the Shannon entropy (bits per byte) of data.
// Higher values indicate more randomness, which is one signal (never
// sufficient on its own) that a string may be a secret.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	entropy := 0.0
	total := float64(len(data))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}
