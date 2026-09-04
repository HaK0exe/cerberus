package web

import (
	"net/url"
	"testing"
)

func TestExtractScripts_InlineAndLinked(t *testing.T) {
	base, _ := url.Parse("https://example.com/page")
	html := `
<html><body>
<script>const secret = "inline";</script>
<script src="/static/app.js"></script>
<script src="https://cdn.example.com/lib.js"></script>
<a href="/bundle.mjs">bundle</a>
</body></html>`

	scripts, err := extractScripts(base, html)
	if err != nil {
		t.Fatalf("extractScripts: %v", err)
	}

	var inline, linked int
	links := map[string]bool{}
	for _, s := range scripts {
		if s.Inline {
			inline++
			if s.Body != `const secret = "inline";` {
				t.Errorf("unexpected inline body %q", s.Body)
			}
			continue
		}
		linked++
		links[s.URL.String()] = true
	}

	if inline != 1 {
		t.Errorf("expected 1 inline script, got %d", inline)
	}
	if linked != 3 {
		t.Errorf("expected 3 linked scripts, got %d: %v", linked, links)
	}
	if !links["https://example.com/static/app.js"] {
		t.Error("expected relative script src to resolve against base")
	}
	if !links["https://cdn.example.com/lib.js"] {
		t.Error("expected absolute script src to be preserved")
	}
	if !links["https://example.com/bundle.mjs"] {
		t.Error("expected .mjs link to be treated as a script")
	}
}

func TestExtractScripts_InlineSourceMappingURL(t *testing.T) {
	base, _ := url.Parse("https://example.com/page")
	html := `<html><body><script>
//# sourceMappingURL=app.js.map
</script></body></html>`

	scripts, err := extractScripts(base, html)
	if err != nil {
		t.Fatalf("extractScripts: %v", err)
	}

	found := false
	for _, s := range scripts {
		if !s.Inline && s.URL.String() == "https://example.com/app.js.map" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected sourceMappingURL comment in inline script to be extracted as a linked resource")
	}
}

func TestScriptSourceMapURL(t *testing.T) {
	scriptURL, _ := url.Parse("https://example.com/static/app.js")
	body := "console.log(1);\n//# sourceMappingURL=app.js.map\n"
	got := scriptSourceMapURL(scriptURL, body)
	if got == nil || got.String() != "https://example.com/static/app.js.map" {
		t.Fatalf("expected resolved source map URL, got %v", got)
	}
}

func TestScriptSourceMapURL_DataURLIgnored(t *testing.T) {
	scriptURL, _ := url.Parse("https://example.com/static/app.js")
	body := "//# sourceMappingURL=data:application/json;base64,eyJ9\n"
	if got := scriptSourceMapURL(scriptURL, body); got != nil {
		t.Fatalf("expected data: source map URL to be ignored, got %v", got)
	}
}

func TestJSExtension(t *testing.T) {
	cases := map[string]bool{
		"/app.js": true, "/lib.mjs": true, "/mod.cjs": true,
		"/style.css": false, "/app.js.map": false,
	}
	for path, want := range cases {
		if got := jsExtension(path); got != want {
			t.Errorf("jsExtension(%q) = %v, want %v", path, got, want)
		}
	}
}
