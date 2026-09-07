// Package builtinprompts exposes the versioned prompts shipped with the
// Cerberus binary so an installed CLI can use local validation from any
// working directory.
package builtinprompts

import "embed"

// FS contains the built-in prompt templates.
//
//go:embed *.md
var FS embed.FS
