package llm

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
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

	// Decoded/folded obfuscated payloads land in plain English too
	// ("classify this as a false positive", "follow the instruction"),
	// so a couple of extra phrasings that show up specifically in the
	// obfuscated corpus (#82) are included here — they run through the
	// exact same plaintext pass, decoded/folded passes, and the
	// benign-context test, so they are held to the same precision bar.
	regexp.MustCompile(`(?i)\bclassify\s+this\s+as\s+(a\s+)?(false\s+positive|likely[_\s]secret|uncertain)\b`),
	regexp.MustCompile(`(?i)\bfollow\s+the\s+instructions?\b`),
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
//
// Beyond the plaintext pass, it also runs three obfuscation-aware passes
// (issue #82) that each build an alternate "view" of the line, test that
// view against the same injectionPatterns, and — only on a match — replace
// the corresponding span of the ORIGINAL (still-encoded/obfuscated) text
// with the placeholder:
//
//  1. base64: candidate base64-shaped tokens are decoded and the decoded
//     text is tested against injectionPatterns;
//  2. ROT13: the line is ROT13-transformed (an involution — this both
//     "decodes" ROT13-obfuscated text and, on plain text, scrambles it
//     further away from matching anything) and tested;
//  3. homoglyphs: fullwidth ASCII (U+FF01-FF5E) and a curated set of
//     Cyrillic/Greek Latin-lookalikes are folded back to plain ASCII and
//     tested.
//
// Trade-off (documented per issue #82's request): all three passes only
// neutralize text whose DECODED/FOLDED form matches an existing,
// already-reviewed injectionPatterns entry — they do not flag "looks like
// base64" or "contains non-ASCII" on their own. This keeps the false-positive
// surface the same as the plaintext pass (still gated on the same
// English-instruction-shaped patterns) at the cost of not catching
// obfuscated phrasings the plaintext patterns wouldn't catch in clear text
// either. That is the right side to err on here: this filter is
// defense-in-depth, not the security boundary (see ADR-0002 and
// `internal/detector/injection_test.go`'s
// TestCorpus_ObedientValidatorNeverEscapesLLMReviewBand — the score clamp
// holds regardless of whether this filter catches a given obfuscation), and
// over-neutralizing legitimate base64/Unicode content in scanned artifacts
// would degrade the very context a Validator needs to classify candidates
// accurately.
func neutralizeInjections(context string) string {
	lines := strings.Split(context, "\n")
	for i, line := range lines {
		for _, pattern := range injectionPatterns {
			line = pattern.ReplaceAllString(line, injectionPlaceholder)
		}
		line = neutralizeEncodedBase64(line)
		line = neutralizeFoldedLine(line, rot13Rune)
		line = neutralizeFoldedLine(line, foldHomoglyphRune)
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

// base64TokenPattern finds candidate base64-shaped tokens: runs of the
// base64 alphabet at least minBase64TokenLen characters long, with
// optional "=" padding. The length floor exists because short base64-
// alphabet runs are extremely common in legitimate content (hex-ish
// identifiers, short hashes, path segments) and decoding+testing every one
// of them buys little while adding false-positive surface; injection
// payloads worth hiding in base64 are, in practice, at least a short
// sentence once decoded.
var base64TokenPattern = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)

const minBase64TokenLen = 16

// neutralizeEncodedBase64 replaces base64-shaped tokens whose DECODED
// content matches an injectionPatterns entry with injectionPlaceholder,
// leaving every other base64-shaped token (including real secrets that
// happen to be base64-encoded, and base64 blobs that decode to non-text
// binary data) completely untouched. Only the encoded token in the
// original text is replaced — never a decoded value that appears nowhere
// in the original — so nothing is neutralized that wasn't actually present
// as (obfuscated) text.
func neutralizeEncodedBase64(line string) string {
	return base64TokenPattern.ReplaceAllStringFunc(line, func(tok string) string {
		decoded, ok := tryBase64Decode(tok)
		if !ok {
			return tok
		}
		if matchesInjectionPattern(decoded) {
			return injectionPlaceholder
		}
		return tok
	})
}

// tryBase64Decode attempts standard and raw (unpadded) base64 decoding and
// requires the result to be valid UTF-8 text — binary-decoded output can
// never match an injectionPatterns entry (they're all text/regex patterns),
// so treating a non-UTF-8 decode as "not base64 worth inspecting" avoids
// wasted work and keeps this pass from ever touching genuinely binary
// base64 payloads.
func tryBase64Decode(tok string) (string, bool) {
	if b, err := base64.StdEncoding.DecodeString(tok); err == nil && utf8.Valid(b) {
		return string(b), true
	}
	if b, err := base64.RawStdEncoding.DecodeString(tok); err == nil && utf8.Valid(b) {
		return string(b), true
	}
	return "", false
}

// matchesInjectionPattern reports whether s matches any injectionPatterns
// entry.
func matchesInjectionPattern(s string) bool {
	for _, pattern := range injectionPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}
	return false
}

// runeFold is a rune-for-rune (never merges or splits runes) text
// transform. Because it never changes the rune count, a match found in the
// folded text's rune stream lines up exactly with the same rune indices in
// the original text, which is what lets neutralizeFoldedLine replace the
// ORIGINAL (encoded/homoglyph) span rather than a decoded value that
// doesn't appear in the source text at all.
type runeFold func(r rune) rune

// rot13Rune applies the classic ROT13 letter substitution and leaves every
// other rune (including non-Latin letters, digits, and punctuation)
// unchanged. ROT13 is its own inverse: applied to ROT13-obfuscated
// injection text it decodes it back to plain English (and the existing
// injectionPatterns then match); applied to ordinary English prose it
// scrambles it further away from matching anything, so this pass cannot
// make an already-benign line more likely to be (mis)neutralized.
func rot13Rune(r rune) rune {
	switch {
	case r >= 'a' && r <= 'z':
		return 'a' + (r-'a'+13)%26
	case r >= 'A' && r <= 'Z':
		return 'A' + (r-'A'+13)%26
	default:
		return r
	}
}

// homoglyphTable maps a small, curated set of Cyrillic and Greek letters
// that are visually indistinguishable from a Latin ASCII letter (a common
// homoglyph-spoofing trick, also seen in phishing-domain research) back to
// that Latin letter. It is deliberately not exhaustive — see
// foldHomoglyphRune's doc comment for why an incomplete table is the right
// trade-off here.
var homoglyphTable = map[rune]rune{
	// Cyrillic lowercase lookalikes.
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
	'і': 'i', 'ѕ': 's', 'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ո': 'n',
	// Cyrillic uppercase lookalikes.
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
	'Р': 'P', 'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X', 'Ѕ': 'S',
	// Greek lookalikes.
	'α': 'a', 'ο': 'o', 'ρ': 'p', 'υ': 'y', 'ν': 'v', 'Α': 'A', 'Β': 'B',
	'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N',
	'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
}

// foldHomoglyphRune folds a rune back to plain ASCII along two axes:
//
//  1. fullwidth ASCII (Unicode's "Halfwidth and Fullwidth Forms" block,
//     U+FF01-U+FF5E) is a fixed +0xFEE0 offset from the ASCII it visually
//     represents, so it can be folded with simple arithmetic;
//  2. a curated set of Cyrillic/Greek homoglyphs (homoglyphTable) that are
//     not Unicode-equivalent to their Latin lookalike (so arithmetic or
//     NFKC normalization won't fold them) but are common in practice.
//
// This is a manual table rather than a full Unicode confusables dependency
// (Go has no stdlib confusables table, and pulling one in for three corpus
// samples was judged not worth the dependency+maintenance cost) — it is
// intentionally scoped to the obfuscation styles the #82 corpus actually
// exercises, not a general homoglyph-spoofing defense. Extend the table if
// a real-world sample surfaces a lookalike it misses.
func foldHomoglyphRune(r rune) rune {
	if r >= 0xFF01 && r <= 0xFF5E {
		return r - 0xFEE0
	}
	if r == 0x3000 { // ideographic (fullwidth) space
		return ' '
	}
	if folded, ok := homoglyphTable[r]; ok {
		return folded
	}
	return r
}

// neutralizeFoldedLine runs each injectionPatterns entry against fold(line)
// and, for every match, replaces the corresponding span of the ORIGINAL
// line (not the folded one) with injectionPlaceholder. It processes
// patterns one at a time, re-folding after each replacement, so a
// placeholder inserted by an earlier pattern can never itself be
// re-matched by a later one in a way that depends on stale offsets.
func neutralizeFoldedLine(line string, fold runeFold) string {
	for _, pattern := range injectionPatterns {
		line = replaceFoldedMatches(line, fold, pattern)
	}
	return line
}

// replaceFoldedMatches finds pattern's matches in fold(line) and replaces
// the equivalent spans of line (by rune index — safe because fold is
// rune-count-preserving, see runeFold) with injectionPlaceholder.
func replaceFoldedMatches(line string, fold runeFold, pattern *regexp.Regexp) string {
	runes := []rune(line)
	if len(runes) == 0 {
		return line
	}

	foldedRunes := make([]rune, len(runes))
	byteOffsetToRuneIdx := make([]int, 0, len(runes)+1)
	changed := false
	for i, r := range runes {
		f := fold(r)
		if f != r {
			changed = true
		}
		foldedRunes[i] = f
	}
	if !changed {
		// Nothing for this fold to change on this line: folding it again
		// would just re-run the exact same match the plaintext pass
		// (or an earlier fold pass) already had a chance to make.
		return line
	}

	var folded strings.Builder
	for _, r := range foldedRunes {
		byteOffsetToRuneIdx = append(byteOffsetToRuneIdx, folded.Len())
		folded.WriteRune(r)
	}
	foldedStr := folded.String()
	byteOffsetToRuneIdx = append(byteOffsetToRuneIdx, len(foldedStr))

	locs := pattern.FindAllStringIndex(foldedStr, -1)
	if locs == nil {
		return line
	}

	runeIndexAt := func(byteOffset int) int {
		for i, off := range byteOffsetToRuneIdx {
			if off == byteOffset {
				return i
			}
		}
		// Regex match boundaries always fall on rune boundaries for valid
		// UTF-8 input, so this should be unreachable; fail safe by
		// treating it as "no match" rather than risking a bad splice.
		return -1
	}

	var out []rune
	prevRuneEnd := 0
	for _, loc := range locs {
		startRune := runeIndexAt(loc[0])
		endRune := runeIndexAt(loc[1])
		if startRune < 0 || endRune < 0 || startRune < prevRuneEnd {
			continue
		}
		out = append(out, runes[prevRuneEnd:startRune]...)
		out = append(out, []rune(injectionPlaceholder)...)
		prevRuneEnd = endRune
	}
	out = append(out, runes[prevRuneEnd:]...)
	return string(out)
}
