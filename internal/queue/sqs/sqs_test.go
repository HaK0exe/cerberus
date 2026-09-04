package sqs

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	awssqs "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func TestPublish_RejectsOversizedPayload(t *testing.T) {
	q := New(&fakeAPI{})
	payload := make([]byte, MaxMessageSize+1)
	err := q.Publish(context.Background(), "https://example.invalid/queue", payload)
	if err == nil {
		t.Fatal("expected an error for a payload exceeding MaxMessageSize")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected a size-limit error, got %v", err)
	}
}

func TestPublish_AllowsMaxSizePayload(t *testing.T) {
	fake := &fakeAPI{}
	q := New(fake)
	payload := make([]byte, MaxMessageSize)
	if err := q.Publish(context.Background(), "https://example.invalid/queue", payload); err != nil {
		t.Fatalf("expected a payload of exactly MaxMessageSize to be allowed, got %v", err)
	}
	if fake.sendCalls != 1 {
		t.Fatalf("expected exactly one SendMessage call, got %d", fake.sendCalls)
	}
}

// fakeAPI is a minimal in-memory API implementation for unit tests
// that don't need a real (or ElasticMQ) SQS endpoint.
type fakeAPI struct {
	mu        sync.Mutex
	messages  []string
	sendCalls int
	deleted   int
}

func (f *fakeAPI) SendMessage(ctx context.Context, params *awssqs.SendMessageInput, optFns ...func(*awssqs.Options)) (*awssqs.SendMessageOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sendCalls++
	f.messages = append(f.messages, *params.MessageBody)
	return &awssqs.SendMessageOutput{}, nil
}

func (f *fakeAPI) ReceiveMessage(ctx context.Context, params *awssqs.ReceiveMessageInput, optFns ...func(*awssqs.Options)) (*awssqs.ReceiveMessageOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.messages) == 0 {
		return &awssqs.ReceiveMessageOutput{}, nil
	}
	body := f.messages[0]
	f.messages = f.messages[1:]
	handle := body
	return &awssqs.ReceiveMessageOutput{
		Messages: []types.Message{{Body: &body, ReceiptHandle: &handle}},
	}, nil
}

func (f *fakeAPI) DeleteMessage(ctx context.Context, params *awssqs.DeleteMessageInput, optFns ...func(*awssqs.Options)) (*awssqs.DeleteMessageOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted++
	return &awssqs.DeleteMessageOutput{}, nil
}

func TestPublishConsume_RoundTrip(t *testing.T) {
	fake := &fakeAPI{}
	q := New(fake)
	q.WaitTimeSeconds = 0 // avoid real long-polling delay in the fake

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := q.Publish(ctx, "q", []byte("hello")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	ch, err := q.Consume(ctx, "q")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}

	select {
	case msg := <-ch:
		if string(msg) != "hello" {
			t.Fatalf("got %q, want %q", msg, "hello")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for message")
	}

	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected channel to close after context cancellation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Consume to exit after cancellation")
	}
}

// TestConsume_ContextCancellation_NoGoroutineLeak verifies Consume's
// goroutine actually exits (channel closes) promptly on cancellation,
// even with no messages ever published — the empty-receive path must
// also respect ctx.
func TestConsume_ContextCancellation_NoGoroutineLeak(t *testing.T) {
	fake := &fakeAPI{}
	q := New(fake)
	q.WaitTimeSeconds = 0

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := q.Consume(ctx, "empty-queue")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}

	// Give the goroutine a moment to start polling, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected no messages and a closed channel")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Consume goroutine did not exit after context cancellation (possible leak)")
	}
}
