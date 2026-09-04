package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRobotsCache_DisallowedPathBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.Write([]byte("User-agent: *\nDisallow: /private\n"))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := newRobotsCache(srv.Client(), nil)
	base, _ := url.Parse(srv.URL)

	allowed, _ := url.Parse(base.String() + "/public")
	disallowed, _ := url.Parse(base.String() + "/private/data")

	if !c.allowed(allowed) {
		t.Error("expected /public to be allowed")
	}
	if c.allowed(disallowed) {
		t.Error("expected /private/data to be disallowed")
	}
}

func TestRobotsCache_FetchFailure_FailsOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	var warned bool
	c := newRobotsCache(srv.Client(), func(string, ...any) { warned = true })
	u, _ := url.Parse(srv.URL + "/anything")

	if !c.allowed(u) {
		t.Fatal("expected robots.txt fetch failure to fail open (allow)")
	}
	if !warned {
		t.Fatal("expected a warning to be emitted on robots.txt fetch failure")
	}
}

func TestRobotsCache_Missing404_Allowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newRobotsCache(srv.Client(), nil)
	u, _ := url.Parse(srv.URL + "/page")
	if !c.allowed(u) {
		t.Fatal("expected missing robots.txt (404) to allow all paths")
	}
}

func TestRobotsCache_CachedPerHost(t *testing.T) {
	fetches := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			fetches++
			w.Write([]byte("User-agent: *\nDisallow:\n"))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := newRobotsCache(srv.Client(), nil)
	u1, _ := url.Parse(srv.URL + "/a")
	u2, _ := url.Parse(srv.URL + "/b")
	c.allowed(u1)
	c.allowed(u2)

	if fetches != 1 {
		t.Fatalf("expected robots.txt to be fetched once and cached, got %d fetches", fetches)
	}
}
