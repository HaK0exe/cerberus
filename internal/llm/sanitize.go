package llm

import (
	"regexp"
	"strings"
)

// secretPlaceholder replaces a redacted raw secret value in context text.
// It is a fixed string regardless of the original secret's length so that
// the placeholder itself cannot be used to infer the secret's length or
// its exact position within the surrounding text.
const secretPlaceholder = "[REDACTED-SECRET]"

// injectionPlaceholder replaces text that looks like an attempt to steer
// the model (a prompt-injection attempt) rather than describe scanned
// content. It stays as inert, visibly-neutralized text so a validator
// still sees that *something* was there (useful context for the
// "uncertain"/suspicious classification) without ever executing it as an
// instruction.
const injectionPlaceholder = "[neutralized-instruction-like-text]"

// injectionPatterns matches text shaped like an attempt to redirect the
// model's behavior: instruction overrides, role/jailbreak prompts, chat
// control tokens, and fabricated validator output trying to spoof a
// ValidationResult. This is intentionally conservative and pattern-based
// (not exhaustive) — see issue S3-09 for the dedicated adversarial corpus
// and precision/recall evaluation of this list.
var injectionPatterns = []*regexp.Regexp{
	// Direct instruction override ("ignore previous instructions", ...).
	regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\s+(all\s+)?(the\s+)?(above|prior|previous|preceding)\s+(instructions?|prompts?|rules?|context)\b`),
	regexp.MustCompile(`(?i)\bnew\s+instructions?\s*:`),
	regexp.MustCompile(`(?i)\bfrom\s+now\s+on\s*,?\s*(you|ignore)\b`),

	// Role-play / jailbreak framing.
	regexp.MustCompile(`(?i)\byou\s+are\s+now\s+(a|an)?\b`),
	regexp.MustCompile(`(?i)\bact\s+as\s+(a|an)\b`),
	regexp.MustCompile(`(?i)\bpretend\s+(you\s+are|to\s+be)\b`),
	regexp.MustCompile(`(?i)\bdo\s+anything\s+now\b`),
	regexp.MustCompile(`(?i)\bjailbreak\b`),
	regexp.MustCompile(`(?i)\bdeveloper\s+mode\b`),

	// Chat/control-token smuggling.
	regexp.MustCompile(`(?i)<\|im_start\|>|<\|im_end\|>`),
	regexp.MustCompile(`(?i)\[/?INST\]`),
	regexp.MustCompile(`(?i)^\s*(system|assistant)\s*:`),

	// Direct attempts to steer the classification outcome, including
	// fabricated JSON that mimics a ValidationResult / ValidationClassification
	// value.
	regexp.MustCompile(`(?i)\bmark\s+(this|it)\s+as\s+(not\s+a\s+secret|a\s+false\s+positive|safe)\b`),
	regexp.MustCompile(`(?i)\brespond\s+(only\s+)?with\s*:?`),
	regexp.MustCompile(`(?i)"?classification"?\s*[:=]\s*"?(likely_false_positive|likely_secret|uncertain)"?`),
	regexp.MustCompile(`(?i)"?confidence"?\s*[:=]\s*[01](\.\d+)?`),
}

// sanitizeContext performs the two-stage redaction Sanitize is contracted
// to provide:
//
//  1. remove the raw candidate secret value, replacing it with a
//     fixed-width placeholder so neither its length nor its exact
//     position leak;
//  2. neutralize prompt-injection-shaped text so a Validator's model never
//     executes attacker-controlled content in the scanned artifact as an
//     instruction.
//
// It is deliberately conservative about what it strips: it must still
// leave enough of the surrounding, non-redacted context for a Validator to
// classify the candidate accurately (see the S3-08 benchmark).
func sanitizeContext(context string, secretValue []byte) string {
	sanitized := redactSecretValue(context, secretValue)
	sanitized = neutralizeInjections(sanitized)
	return sanitized
}

// redactSecretValue replaces every occurrence of the raw secret value in
// context with a fixed-width placeholder. Matching is exact-byte: this is
// the same value the detector matched, not a fuzzy/normalized form, so
// there is nothing to reverse-engineer from either the presence or the
// absence of a match.
func redactSecretValue(context string, secretValue []byte) string {
	if len(secretValue) == 0 {
		return context
	}
	return strings.ReplaceAll(context, string(secretValue), secretPlaceholder)
}

// neutralizeInjections replaces every span matching injectionPatterns with
// injectionPlaceholder, line by line (so a "system:"-style prefix match
// stays anchored to its own line rather than spanning across the whole
// context).
func neutralizeInjections(context string) string {
	lines := strings.Split(context, "\n")
	for i, line := range lines {
		for _, pattern := range injectionPatterns {
			line = pattern.ReplaceAllString(line, injectionPlaceholder)
		}
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}
