package frontier

import (
	"context"
	"sync"
	"testing"

	"github.com/HaK0exe/cerberus/internal/queue"
)

func TestCanonicalize(t *testing.T) {
	cases := map[string]string{
		"https://Example.com":              "https://example.com/",
		"https://example.com/":             "https://example.com/",
		"https://example.com:443/path/":    "https://example.com/path",
		"http://example.com:80/path":       "http://example.com/path",
		"https://example.com/path?b=2&a=1": "https://example.com/path?a=1&b=2",
	}
	for in, want := range cases {
		got, err := Canonicalize(in)
		if err != nil {
			t.Fatalf("Canonicalize(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("Canonicalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonicalize_EquivalentURLsMatch(t *testing.T) {
	a, _ := Canonicalize("https://example.com:443/path/?x=1&y=2")
	b, _ := Canonicalize("https://EXAMPLE.com/path?y=2&x=1")
	if a != b {
		t.Fatalf("expected equivalent URLs to canonicalize identically: %q vs %q", a, b)
	}
}

func TestInMemoryDeduper_MarkIfNew(t *testing.T) {
	d := NewInMemoryDeduper()
	if !d.MarkIfNew("https://example.com/") {
		t.Fatal("expected first mark to be new")
	}
	if d.MarkIfNew("https://example.com/") {
		t.Fatal("expected second mark of the same URL to not be new")
	}
}

// TestFrontier_MultipleWorkersNoDuplicateFetch is the core S2-11
// acceptance criterion: two or more workers consuming the same
// frontier (same queue, same shared Deduper) must not both end up
// with the same canonical URL to fetch, even when several producers
// race to enqueue overlapping link sets concurrently.
func TestFrontier_MultipleWorkersNoDuplicateFetch(t *testing.T) {
	q := queue.NewMemQueue(256)
	dedup := NewInMemoryDeduper()
	f := New(q, "web-frontier:scan-1", dedup)

	ctx := context.Background()
	urls := []string{
		"https://example.com/a",
		"https://example.com/a/", // same canonical URL as /a
		"https://example.com/b",
		"https://example.com/b?x=1",
		"https://EXAMPLE.com/c",
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	pushed := 0
	// Simulate multiple producers discovering (overlapping) links
	// concurrently.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, u := range urls {
				ok, err := f.Push(ctx, "scan-1", u, 1)
				if err != nil {
					t.Errorf("Push(%q): %v", u, err)
					return
				}
				if ok {
					mu.Lock()
					pushed++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	// 4 distinct canonical URLs among the 5 (a and a/ collapse).
	if pushed != 4 {
		t.Fatalf("expected exactly 4 unique canonical URLs pushed, got %d", pushed)
	}

	msgs, err := f.Consume(ctx)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}

	seenByWorker := make(map[string]bool)
	var wmu sync.Mutex
	var wg2 sync.WaitGroup
	fetches := 0
	var fmu sync.Mutex

	consumeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for w := 0; w < 3; w++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			for {
				select {
				case msg, ok := <-msgs:
					if !ok {
						return
					}
					wmu.Lock()
					dup := seenByWorker[msg.URL]
					seenByWorker[msg.URL] = true
					wmu.Unlock()
					if dup {
						t.Errorf("worker received duplicate canonical URL %q", msg.URL)
					}
					fmu.Lock()
					fetches++
					done := fetches == 4
					fmu.Unlock()
					if done {
						cancel()
						return
					}
				case <-consumeCtx.Done():
					return
				}
			}
		}()
	}
	wg2.Wait()

	if fetches != 4 {
		t.Fatalf("expected 4 total fetches across workers, got %d", fetches)
	}
}

func TestMessage_MarshalUnmarshal(t *testing.T) {
	m := Message{ScanID: "scan-1", URL: "https://example.com/", Depth: 2}
	payload, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := Unmarshal(payload)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got != m {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, m)
	}
}
