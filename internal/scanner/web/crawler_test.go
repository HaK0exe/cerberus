package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HaK0exe/cerberus/internal/scanner/web/ssrf"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// permissiveTestGuard allows loopback (httptest servers listen on
// 127.0.0.1) so functional crawler tests can exercise real
// request/redirect/link-following behavior without that being
// conflated with SSRF blocking itself, which the ssrf package and
// TestSecurity_* below cover directly.
func permissiveTestGuard() *ssrf.Guard {
	g := ssrf.NewGuard()
	var nets []*net.IPNet
	for _, c := range ssrf.DefaultBlockedCIDRs {
		if c == "127.0.0.0/8" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		nets = append(nets, n)
	}
	g.BlockedNets = nets
	return g
}

func drain(t *testing.T, ch <-chan cerberus.Artifact, timeout time.Duration) []cerberus.Artifact {
	t.Helper()
	var out []cerberus.Artifact
	deadline := time.After(timeout)
	for {
		select {
		case a, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, a)
		case <-deadline:
			t.Fatal("timed out waiting for crawl to finish")
		}
	}
}

func TestCrawler_FetchesPageAndFollowsLinks(t *testing.T) {
	var mux http.ServeMux
	var srv *httptest.Server
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body><a href="/child">child</a></body></html>`)
	})
	mux.HandleFunc("/child", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>leaf</body></html>`)
	})
	srv = httptest.NewServer(&mux)
	defer srv.Close()

	cr := &Crawler{Guard: permissiveTestGuard()}
	ch, err := cr.Scan(context.Background(), srv.URL, cerberus.ScanOptions{
		Depth: 2, MaxPages: 10, Concurrency: 2, RateLimit: 1000,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	artifacts := drain(t, ch, 5*time.Second)

	var pages int
	for _, a := range artifacts {
		if a.SourceType == cerberus.SourceWebPage {
			pages++
		}
	}
	if pages != 2 {
		t.Fatalf("expected 2 pages fetched (root + child), got %d: %+v", pages, artifacts)
	}
}

func TestCrawler_MaxPagesBounds(t *testing.T) {
	var mux http.ServeMux
	var srv *httptest.Server
	for i := 0; i < 20; i++ {
		i := i
		mux.HandleFunc(fmt.Sprintf("/p%d", i), func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `<html><body><a href="/p%d">next</a></body></html>`, i+1)
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><a href="/p0">next</a></body></html>`)
	})
	srv = httptest.NewServer(&mux)
	defer srv.Close()

	cr := &Crawler{Guard: permissiveTestGuard()}
	ch, err := cr.Scan(context.Background(), srv.URL, cerberus.ScanOptions{
		Depth: 50, MaxPages: 5, Concurrency: 1, RateLimit: 1000,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	artifacts := drain(t, ch, 5*time.Second)
	if len(artifacts) > 6 { // small slack: budget check happens per-request, not perfectly exact
		t.Fatalf("expected roughly MaxPages artifacts, got %d", len(artifacts))
	}
}

// newLoopbackServer binds to a distinct loopback address (127.0.0.x)
// so tests can distinguish "on-scope" and "off-scope" test servers by
// hostname the way Scope actually does (domain, not port).
func newLoopbackServer(t *testing.T, ip string, handler http.Handler) *httptest.Server {
	t.Helper()
	lis, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Fatalf("listening on %s: %v", ip, err)
	}
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	return srv
}

func TestCrawler_ScopeBlocksOffDomainLink(t *testing.T) {
	offSrv := newLoopbackServer(t, "127.0.0.2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("off-scope server should never be fetched")
	}))
	defer offSrv.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body><a href="%s/evil">offsite</a></body></html>`, offSrv.URL)
	})
	onSrv := newLoopbackServer(t, "127.0.0.1", mux)
	defer onSrv.Close()

	cr := &Crawler{Guard: permissiveTestGuard()}
	ch, err := cr.Scan(context.Background(), onSrv.URL, cerberus.ScanOptions{
		Depth: 2, MaxPages: 10, Concurrency: 1, RateLimit: 1000,
		AllowedDomains: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	drain(t, ch, 3*time.Second)
}

func TestCrawler_ScopeBlocksOffDomainRedirect(t *testing.T) {
	offSrv := newLoopbackServer(t, "127.0.0.2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("off-scope redirect target should never be fetched")
	}))
	defer offSrv.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, offSrv.URL+"/evil", http.StatusFound)
	})
	onSrv := newLoopbackServer(t, "127.0.0.1", mux)
	defer onSrv.Close()

	cr := &Crawler{Guard: permissiveTestGuard()}
	ch, err := cr.Scan(context.Background(), onSrv.URL, cerberus.ScanOptions{
		Depth: 1, MaxPages: 5, Concurrency: 1, RateLimit: 1000,
		AllowedDomains: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	artifacts := drain(t, ch, 3*time.Second)
	for _, a := range artifacts {
		if strings.Contains(a.URI, offSrv.URL) {
			t.Fatalf("expected no artifact from off-scope redirect target, got %+v", a)
		}
	}
}

func TestCrawler_RespectsRobotsTxt(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /private\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body><a href="/private">nope</a></body></html>`)
	})
	mux.HandleFunc("/private", func(w http.ResponseWriter, r *http.Request) {
		t.Error("/private must not be fetched when robots.txt is respected")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cr := &Crawler{Guard: permissiveTestGuard()}
	ch, err := cr.Scan(context.Background(), srv.URL, cerberus.ScanOptions{
		Depth: 2, MaxPages: 10, Concurrency: 1, RateLimit: 1000,
		RespectRobots: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	drain(t, ch, 3*time.Second)
}

func TestCrawler_IgnoreRobots_FetchesDisallowed(t *testing.T) {
	fetched := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /private\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body><a href="/private">yes</a></body></html>`)
	})
	mux.HandleFunc("/private", func(w http.ResponseWriter, r *http.Request) {
		select {
		case fetched <- struct{}{}:
		default:
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cr := &Crawler{Guard: permissiveTestGuard()}
	ch, err := cr.Scan(context.Background(), srv.URL, cerberus.ScanOptions{
		Depth: 2, MaxPages: 10, Concurrency: 1, RateLimit: 1000,
		RespectRobots: false,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	drain(t, ch, 3*time.Second)

	select {
	case <-fetched:
	default:
		t.Fatal("expected /private to be fetched with RespectRobots=false")
	}
}

func TestCrawler_ExtractsInlineAndLinkedJS(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><script>var x = "inline-secret";</script><script src="/app.js"></script></body></html>`)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `var linked = "linked-secret";`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cr := &Crawler{Guard: permissiveTestGuard()}
	ch, err := cr.Scan(context.Background(), srv.URL, cerberus.ScanOptions{
		Depth: 1, MaxPages: 10, Concurrency: 1, RateLimit: 1000,
		ScanJavaScript: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	artifacts := drain(t, ch, 3*time.Second)

	var inlineFound, linkedFound bool
	for _, a := range artifacts {
		if a.SourceType != cerberus.SourceWebScript {
			continue
		}
		if strings.Contains(string(a.Content), "inline-secret") {
			inlineFound = true
		}
		if strings.Contains(string(a.Content), "linked-secret") {
			linkedFound = true
		}
	}
	if !inlineFound {
		t.Error("expected inline script artifact")
	}
	if !linkedFound {
		t.Errorf("expected linked script artifact, got artifacts: %+v", artifacts)
	}
}

func TestCrawler_ScanJavaScriptFalse_DisablesJSPipeline(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><script>var x = "inline-secret";</script><script src="/app.js"></script></body></html>`)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		t.Error("linked JS must not be fetched when ScanJavaScript is false")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cr := &Crawler{Guard: permissiveTestGuard()}
	ch, err := cr.Scan(context.Background(), srv.URL, cerberus.ScanOptions{
		Depth: 1, MaxPages: 10, Concurrency: 1, RateLimit: 1000,
		ScanJavaScript: false,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	artifacts := drain(t, ch, 3*time.Second)
	for _, a := range artifacts {
		if a.SourceType == cerberus.SourceWebScript {
			t.Fatalf("expected no script artifacts, got %+v", a)
		}
	}
}
