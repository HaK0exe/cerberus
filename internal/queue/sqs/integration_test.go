// Integration test against a real SQS-compatible endpoint
// (ElasticMQ), covering the round-trip acceptance criterion from
// S2-10 that the fakeAPI-based unit tests in sqs_test.go can't: real
// wire encoding, a real long-poll ReceiveMessage, and real
// SendMessage/DeleteMessage semantics.
//
// It starts an ElasticMQ container via the docker CLI (no
// testcontainers dependency) and skips cleanly — not fails — when
// docker isn't available, so `go test ./...` stays green on machines
// without it.
package sqs

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awssqs "github.com/aws/aws-sdk-go-v2/service/sqs"
)

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available: skipping ElasticMQ integration test")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not reachable: skipping ElasticMQ integration test")
	}
}

// startElasticMQ launches an ElasticMQ container bound to a free host
// port and returns its base endpoint URL, tearing the container down
// on test cleanup.
func startElasticMQ(t *testing.T) string {
	t.Helper()
	requireDocker(t)

	port := freePort(t)
	name := fmt.Sprintf("cerberus-elasticmq-test-%d", time.Now().UnixNano())

	runArgs := []string{
		"run", "-d", "--rm",
		"--name", name,
		"-p", fmt.Sprintf("%d:9324", port),
		"softwaremill/elasticmq-native:latest",
	}
	if out, err := exec.Command("docker", runArgs...).CombinedOutput(); err != nil {
		t.Skipf("could not start ElasticMQ container (skipping): %v: %s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})

	endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForElasticMQ(t, endpoint)
	return endpoint
}

func freePort(t *testing.T) int {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	defer lis.Close()
	return lis.Addr().(*net.TCPAddr).Port
}

func waitForElasticMQ(t *testing.T, endpoint string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Post(endpoint, "text/plain", strings.NewReader("Action=ListQueues&Version=2012-11-05"))
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("ElasticMQ at %s did not become ready in time", endpoint)
}

func newTestClient(t *testing.T, endpoint string) *awssqs.Client {
	t.Helper()
	return awssqs.New(awssqs.Options{
		Region:       "elasticmq",
		BaseEndpoint: awsconfig.String(endpoint),
		Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
	})
}

func createQueue(t *testing.T, client *awssqs.Client, name string) string {
	t.Helper()
	out, err := client.CreateQueue(context.Background(), &awssqs.CreateQueueInput{QueueName: &name})
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	return *out.QueueUrl
}

func TestIntegration_PublishConsume_RoundTrip(t *testing.T) {
	endpoint := startElasticMQ(t)
	client := newTestClient(t, endpoint)
	queueURL := createQueue(t, client, "cerberus-test-"+strconv.FormatInt(time.Now().UnixNano(), 10))

	q := New(client)
	q.WaitTimeSeconds = 2

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	want := []string{"web-frontier:1", "web-frontier:2", "web-frontier:3"}
	for _, msg := range want {
		if err := q.Publish(ctx, queueURL, []byte(msg)); err != nil {
			t.Fatalf("Publish(%q): %v", msg, err)
		}
	}

	ch, err := q.Consume(ctx, queueURL)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}

	got := make(map[string]bool)
	for len(got) < len(want) {
		select {
		case msg, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed early, got %d/%d messages", len(got), len(want))
			}
			got[string(msg)] = true
		case <-ctx.Done():
			t.Fatalf("timed out with %d/%d messages received", len(got), len(want))
		}
	}
	for _, msg := range want {
		if !got[msg] {
			t.Errorf("expected to receive %q, did not", msg)
		}
	}
}

// TestIntegration_ConsumeRespectsContextCancellation proves the real
// (not faked) long-poll ReceiveMessage loop against ElasticMQ also
// exits cleanly on cancellation — no goroutine left blocked in a real
// long-poll call.
func TestIntegration_ConsumeRespectsContextCancellation(t *testing.T) {
	endpoint := startElasticMQ(t)
	client := newTestClient(t, endpoint)
	queueURL := createQueue(t, client, "cerberus-test-cancel-"+strconv.FormatInt(time.Now().UnixNano(), 10))

	q := New(client)
	q.WaitTimeSeconds = 20 // a real long poll, to prove cancellation interrupts it rather than waiting it out

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := q.Consume(ctx, queueURL)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}

	time.Sleep(500 * time.Millisecond) // let the long poll actually start
	start := time.Now()
	cancel()

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected channel to close, not deliver a message")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Consume did not exit within 10s of cancellation (possible goroutine leak / blocked long poll)")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Consume took %s to exit after cancellation; expected it to interrupt the long poll promptly", elapsed)
	}
}
