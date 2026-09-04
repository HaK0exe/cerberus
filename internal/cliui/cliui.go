// Package cliui provides the shared terminal-output primitives used by
// the cerberus CLI: verbosity-gated logging, severity coloring, the
// startup banner, and a single-line crawl progress indicator. It is
// what makes `cerberus` read like sqlmap/katana instead of a bag of
// unrelated fmt.Println calls: quiet by default, chatty on -v, and
// color-aware without ever corrupting piped/machine-readable output
// (color and the banner are both gated on the destination being a
// real terminal, and by --no-color / NO_COLOR).
package cliui

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Level is the verbosity level: how much of what the CLI does gets
// surfaced on stderr. Findings/results themselves (stdout) are never
// gated by Level — only diagnostic chatter is.
type Level int

const (
	// LevelQuiet suppresses all diagnostic output (--quiet).
	LevelQuiet Level = iota
	// LevelWarn is the default: warnings and the banner, nothing else.
	LevelWarn
	// LevelInfo adds progress/info messages (-v).
	LevelInfo
	// LevelDebug adds per-request diagnostics (-vv), e.g. every
	// robots.txt/TLS fetch failure during a web crawl.
	LevelDebug
)

const (
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
	red     = "\x1b[31m"
	boldRed = "\x1b[1;31m"
	yellow  = "\x1b[33m"
	cyan    = "\x1b[36m"
	gray    = "\x1b[90m"
	green   = "\x1b[32m"
)

// UI is the sink for everything the CLI prints outside of the actual
// scan results (findings themselves are still written directly to
// stdout by the caller, via renderFindings).
type UI struct {
	Out, Err io.Writer
	Level    Level
	Color    bool

	progressActive bool
}

// New builds a UI from the CLI's global flags. verbosity is the count
// of -v occurrences (0, 1, 2, ...); quiet overrides it to LevelQuiet.
func New(out, err io.Writer, quiet bool, verbosity int, noColor bool) *UI {
	level := LevelWarn
	switch {
	case quiet:
		level = LevelQuiet
	case verbosity >= 2:
		level = LevelDebug
	case verbosity == 1:
		level = LevelInfo
	}

	color := !noColor && os.Getenv("NO_COLOR") == "" && isTerminal(err)

	return &UI{Out: out, Err: err, Level: level, Color: color}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func (u *UI) colorize(code, s string) string {
	if !u.Color {
		return s
	}
	return code + s + reset
}

// Severity renders a severity label (e.g. "critical") uppercased and
// color-coded, for inclusion in a findings line.
func (u *UI) Severity(sev string) string {
	label := strings.ToUpper(sev)
	switch strings.ToLower(sev) {
	case "critical":
		return u.colorize(boldRed, label)
	case "high":
		return u.colorize(red, label)
	case "medium":
		return u.colorize(yellow, label)
	case "low":
		return u.colorize(cyan, label)
	default:
		return u.colorize(gray, label)
	}
}

// Ok renders s in green (used for the "no findings" line).
func (u *UI) Ok(s string) string { return u.colorize(green, s) }

// Warnf prints a warning at LevelWarn and above (the default level).
func (u *UI) Warnf(format string, args ...any) {
	u.endProgress()
	if u.Level < LevelWarn {
		return
	}
	fmt.Fprintf(u.Err, u.colorize(yellow, "[!]")+" "+format+"\n", args...)
}

// Infof prints a progress/status message, shown from -v up.
func (u *UI) Infof(format string, args ...any) {
	u.endProgress()
	if u.Level < LevelInfo {
		return
	}
	fmt.Fprintf(u.Err, u.colorize(cyan, "[*]")+" "+format+"\n", args...)
}

// Debugf prints a per-request diagnostic, shown only from -vv up.
func (u *UI) Debugf(format string, args ...any) {
	u.endProgress()
	if u.Level < LevelDebug {
		return
	}
	fmt.Fprintf(u.Err, u.colorize(gray, "[debug]")+" "+format+"\n", args...)
}

// Progress overwrites a single status line on stderr (like a crawl's
// "N pages fetched" counter). It is a no-op below LevelWarn (--quiet)
// and when stderr isn't a real terminal, so it never litters logs or
// CI output with carriage returns.
func (u *UI) Progress(format string, args ...any) {
	if u.Level == LevelQuiet || !isTerminal(u.Err) {
		return
	}
	fmt.Fprintf(u.Err, "\r\x1b[K"+u.colorize(cyan, "[*] ")+format, args...)
	u.progressActive = true
}

// endProgress clears any in-progress status line before a real log
// line is written, so the two don't collide on the same row.
func (u *UI) endProgress() {
	if !u.progressActive {
		return
	}
	if isTerminal(u.Err) {
		fmt.Fprint(u.Err, "\r\x1b[K")
	}
	u.progressActive = false
}

// DoneProgress clears the progress line at the end of a run (e.g. once
// a crawl finishes) without printing anything in its place.
func (u *UI) DoneProgress() { u.endProgress() }

const banner = `
   ______           __  ,__
  / ____/__  _____ / /_/ /_  ___  _______  ___  _______
 / /   / _ \/ ___/ / __/ __ \/ _ \/ ___/ / / / _ \/ ___/
/ /___/  __/ /  / / /_/ /_/ /  __/ /  / /_/ /  __(__  )
\____/\___/_/  /_/\__/_.___/\___/_/   \__,_/\___/____/
`

// Banner prints the startup banner to stderr. It never fires below
// LevelWarn (--quiet), and only when stderr is a real terminal — a
// script piping cerberus's stdout, or a CI log, never sees it.
func (u *UI) Banner(version string) {
	if u.Level == LevelQuiet || !isTerminal(u.Err) {
		return
	}
	fmt.Fprint(u.Err, u.colorize(cyan, banner))
	fmt.Fprintf(u.Err, "%s  %s\n\n",
		u.colorize(bold, "secret detection, qualification & controlled remediation"),
		u.colorize(gray, "v"+version))
}
