package cerberus

// Candidate is a raw match produced by a rule before scoring and
// context analysis have run. It MAY still hold the raw secret value in
// memory (see internal/policy for lifecycle/zeroing rules) but must
// never be persisted or logged as-is.
type Candidate struct {
	RuleID string

	Start int
	End   int

	Value []byte

	Entropy    float64
	Context    string
	Confidence float64
}
