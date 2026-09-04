package web

import (
	"net/url"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	return u
}

func TestScope_NoAllowedDomains_AllowsAny(t *testing.T) {
	s := Scope{}
	if !s.Allowed(mustURL(t, "https://anything.example/")) {
		t.Fatal("expected empty allowlist to allow any domain")
	}
}

func TestScope_AllowedDomains_ExactAndSubdomain(t *testing.T) {
	s := Scope{AllowedDomains: []string{"example.com"}}
	cases := map[string]bool{
		"https://example.com/":         true,
		"https://www.example.com/":     true,
		"https://sub.example.com/x":    true,
		"https://evil-example.com/":    false,
		"https://example.com.evil.tv/": false,
		"https://other.org/":           false,
	}
	for raw, want := range cases {
		got := s.Allowed(mustURL(t, raw))
		if got != want {
			t.Errorf("%s: got %v, want %v", raw, got, want)
		}
	}
}

func TestScope_ExcludePaths(t *testing.T) {
	s := Scope{ExcludePaths: []string{"/admin", "/private"}}
	if s.Allowed(mustURL(t, "https://example.com/admin/panel")) {
		t.Fatal("expected /admin prefix to be excluded")
	}
	if !s.Allowed(mustURL(t, "https://example.com/public")) {
		t.Fatal("expected /public to be allowed")
	}
}
