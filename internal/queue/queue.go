// Package queue provides cerberus.JobQueue implementations. The
// in-memory queue backs local/CLI runs; SQS backs AWS deployments
// (Sprint 4 — see internal/queue/sqs, not yet implemented).
package queue

import (
	"context"
	"sync"
)

// MemQueue is an in-memory, single-process cerberus.JobQueue used for
// local development and tests.
type MemQueue struct {
	mu      sync.Mutex
	queues  map[string]chan []byte
	bufSize int
}

func NewMemQueue(bufSize int) *MemQueue {
	if bufSize <= 0 {
		bufSize = 64
	}
	return &MemQueue{queues: make(map[string]chan []byte), bufSize: bufSize}
}

func (q *MemQueue) chanFor(name string) chan []byte {
	q.mu.Lock()
	defer q.mu.Unlock()
	ch, ok := q.queues[name]
	if !ok {
		ch = make(chan []byte, q.bufSize)
		q.queues[name] = ch
	}
	return ch
}

func (q *MemQueue) Publish(ctx context.Context, queue string, payload []byte) error {
	select {
	case q.chanFor(queue) <- payload:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (q *MemQueue) Consume(ctx context.Context, queue string) (<-chan []byte, error) {
	return q.chanFor(queue), nil
}
