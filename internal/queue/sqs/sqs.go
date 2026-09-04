// Package sqs implements cerberus.JobQueue against AWS SQS (or any
// SQS-compatible endpoint, e.g. ElasticMQ for local dev/tests). It
// backs cloud deployments; internal/queue.MemQueue backs local/CLI
// runs. No AWS credentials or client construction leak into
// pkg/cerberus — callers build an *sqs.Client (or any API
// implementation) themselves and hand it to New.
package sqs

import (
	"context"
	"errors"
	"fmt"
	"time"

	awssqs "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

var _ cerberus.JobQueue = (*Queue)(nil)

// MaxMessageSize is the hard limit SQS enforces on a message body (256
// KiB, standard queues, no S3 extended-client offload). Publish
// rejects anything larger up front with a clear error instead of
// letting it surface as an opaque API error from AWS.
const MaxMessageSize = 256 * 1024

// defaultWaitTimeSeconds is the long-poll duration used when
// Queue.WaitTimeSeconds is unset. 20s is the SQS-side maximum and
// minimizes empty-receive API calls compared to short polling.
const defaultWaitTimeSeconds = 20

// defaultMaxMessages is how many messages a single ReceiveMessage
// call asks for; 10 is the SQS-side maximum.
const defaultMaxMessages = 10

// pollBackoff is how long Consume waits before retrying after a
// ReceiveMessage error, so a persistent failure (bad credentials,
// queue deleted, ...) doesn't spin-loop against the API.
const pollBackoff = 2 * time.Second

// API is the subset of *sqs.Client this package depends on, so tests
// (and callers who want a different transport) can substitute a fake
// without pulling in a real AWS or ElasticMQ endpoint.
type API interface {
	SendMessage(ctx context.Context, params *awssqs.SendMessageInput, optFns ...func(*awssqs.Options)) (*awssqs.SendMessageOutput, error)
	ReceiveMessage(ctx context.Context, params *awssqs.ReceiveMessageInput, optFns ...func(*awssqs.Options)) (*awssqs.ReceiveMessageOutput, error)
	DeleteMessage(ctx context.Context, params *awssqs.DeleteMessageInput, optFns ...func(*awssqs.Options)) (*awssqs.DeleteMessageOutput, error)
}

// Queue implements cerberus.JobQueue against SQS. The `queue`
// argument every cerberus.JobQueue method takes is the queue's full
// SQS URL (SQS addresses SendMessage/ReceiveMessage/DeleteMessage by
// URL, not by the short symbolic name used elsewhere in this
// project), e.g. "https://sqs.us-east-1.amazonaws.com/123456789012/cerberus-web-frontier".
type Queue struct {
	Client API

	// WaitTimeSeconds configures long-poll receive (0-20). Defaults to
	// 20 when zero.
	WaitTimeSeconds int32
	// VisibilityTimeout, in seconds, bounds how long a received
	// message is hidden from other consumers before SQS assumes the
	// receiver died and redelivers it. Defaults to the queue's own
	// configured visibility timeout when zero (i.e. this field is not
	// sent to SQS at all).
	VisibilityTimeout int32
}

// New returns a Queue backed by client (typically *sqs.Client, or a
// fake implementing API in tests).
func New(client API) *Queue { return &Queue{Client: client} }

func (q *Queue) waitTimeSeconds() int32 {
	if q.WaitTimeSeconds > 0 {
		return q.WaitTimeSeconds
	}
	return defaultWaitTimeSeconds
}

// Publish sends payload as a single SQS message body. It errors
// without making an API call if payload exceeds MaxMessageSize.
func (q *Queue) Publish(ctx context.Context, queue string, payload []byte) error {
	if len(payload) > MaxMessageSize {
		return fmt.Errorf("sqs: payload of %d bytes exceeds the %d byte SQS message size limit", len(payload), MaxMessageSize)
	}
	body := string(payload)
	if _, err := q.Client.SendMessage(ctx, &awssqs.SendMessageInput{
		QueueUrl:    &queue,
		MessageBody: &body,
	}); err != nil {
		return fmt.Errorf("sqs: publishing to %s: %w", queue, err)
	}
	return nil
}

// Consume long-polls queue and streams message bodies on the returned
// channel. Each message is deleted (acknowledged) as soon as it is
// handed to the channel — cerberus.JobQueue has no separate ack step,
// so a consumer that crashes after receiving a message but before
// finishing work on it will not see that message redelivered. This
// matches MemQueue's equally simple at-most-once-after-delivery
// semantics; a future at-least-once mode would need a JobQueue
// interface change to expose an explicit Ack, which is out of this
// package's scope.
//
// The returned channel is closed and the consuming goroutine exits
// promptly when ctx is done — no goroutine is left running past
// cancellation.
func (q *Queue) Consume(ctx context.Context, queue string) (<-chan []byte, error) {
	out := make(chan []byte)

	go func() {
		defer close(out)
		for {
			if ctx.Err() != nil {
				return
			}

			resp, err := q.Client.ReceiveMessage(ctx, &awssqs.ReceiveMessageInput{
				QueueUrl:            &queue,
				MaxNumberOfMessages: defaultMaxMessages,
				WaitTimeSeconds:     q.waitTimeSeconds(),
				VisibilityTimeout:   q.VisibilityTimeout,
			})
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return
				}
				select {
				case <-time.After(pollBackoff):
					continue
				case <-ctx.Done():
					return
				}
			}

			for _, m := range resp.Messages {
				body := messageBody(m)
				select {
				case out <- body:
				case <-ctx.Done():
					return
				}
				if m.ReceiptHandle != nil {
					_, _ = q.Client.DeleteMessage(ctx, &awssqs.DeleteMessageInput{
						QueueUrl:      &queue,
						ReceiptHandle: m.ReceiptHandle,
					})
				}
			}
		}
	}()

	return out, nil
}

func messageBody(m types.Message) []byte {
	if m.Body == nil {
		return nil
	}
	return []byte(*m.Body)
}
