// Package cerberus defines the public domain types shared across all
// Cerberus components (core, scanners, storage, API, MCP).
//
// This package must never import internal/* implementation packages,
// nor anything cloud-, HTTP-, or LLM-specific: it is the stable contract
// the rest of the system is built around.
package cerberus

import "time"

// SourceType identifies where an Artifact originated from.
type SourceType string

const (
	SourceGitWorkingTree SourceType = "git_working_tree"
	SourceGitStaged      SourceType = "git_staged"
	SourceGitCommit      SourceType = "git_commit"
	SourceWebPage        SourceType = "web_page"
	SourceWebScript      SourceType = "web_script"
	SourceFile           SourceType = "file"
	SourceCI             SourceType = "ci"
)

// Artifact is a unit of content submitted to the detection pipeline.
// It carries only what detectors need: identity, provenance, and bytes.
type Artifact struct {
	ID         string
	SourceType SourceType

	URI      string
	Path     string
	Commit   string
	MIMEType string

	Content []byte

	Metadata map[string]string

	FetchedAt time.Time
}
