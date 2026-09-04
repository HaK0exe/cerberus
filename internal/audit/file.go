package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// FileSink appends one JSON object per Event, newline-delimited, to an
// underlying file — an append-only, human-inspectable audit trail
// suitable for `cerberus mcp serve` and other long-running commands
// that need audit persistence without a database. Concurrent Record
// calls are serialized so lines are never interleaved.
type FileSink struct {
	mu sync.Mutex
	w  io.Writer
	c  io.Closer
}

// OpenFileSink opens (creating if necessary) an append-only file at
// path for use as a FileSink. The caller must Close it when done.
func OpenFileSink(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- path is an operator-supplied audit log destination
	if err != nil {
		return nil, fmt.Errorf("opening audit log %s: %w", path, err)
	}
	return &FileSink{w: f, c: f}, nil
}

// NewFileSink wraps an arbitrary writer (e.g. os.Stderr, a test
// buffer) as a FileSink. The returned sink's Close is a no-op unless
// w also implements io.Closer.
func NewFileSink(w io.Writer) *FileSink {
	c, _ := w.(io.Closer)
	return &FileSink{w: w, c: c}
}

func (s *FileSink) Record(_ context.Context, e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	enc := json.NewEncoder(s.w)
	return enc.Encode(e)
}

// Close releases the underlying file, if any. Safe to call on a sink
// built from a writer that isn't itself an io.Closer.
func (s *FileSink) Close() error {
	if s.c == nil {
		return nil
	}
	return s.c.Close()
}
