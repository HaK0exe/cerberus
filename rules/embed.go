// Package builtinrules exposes the detection rules shipped with the
// Cerberus binary. Callers may still load an operator-supplied ruleset
// from disk, but the default CLI must not depend on its working directory.
package builtinrules

import "embed"

// FS contains the built-in provider rule files.
//
//go:embed */*.yaml
var FS embed.FS
