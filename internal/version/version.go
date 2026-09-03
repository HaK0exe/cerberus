// Package version holds build-time version metadata, injected via
// -ldflags at release build time (see Makefile).
package version

var (
	Version   = "0.0.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)
