package web

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// maxScriptBytes bounds how large a single linked script (or its
// source map) we will download and hold in memory — decompression
// bomb / oversized body protection for S2-09's size-limit requirement.
const maxScriptBytes = 25 * 1024 * 1024 // 25MB

// sourceMappingRe matches a //# sourceMappingURL=... (or the legacy
// //@ form) comment, which may appear in linked or inline scripts.
var sourceMappingRe = regexp.MustCompile(`(?m)//[@#]\s*sourceMappingURL=(\S+)`)

// jsExtension reports whether path looks like a JavaScript resource
// by extension (.js, .mjs, .cjs), ignoring query/fragment.
func jsExtension(path string) bool {
	for _, ext := range []string{".js", ".mjs", ".cjs"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// extractedScript is one JS resource discovered on a page: either
// inline content or a link to a linked script/source map.
type extractedScript struct {
	Inline bool
	Body   string   // inline source (Inline == true)
	URL    *url.URL // resolved absolute URL (Inline == false)
}

// extractScripts parses HTML and returns inline script bodies plus
// resolved, absolute URLs for linked scripts and any source maps they
// reference. base is the page URL, used to resolve relative links.
func extractScripts(base *url.URL, htmlBody string) ([]extractedScript, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlBody))
	if err != nil {
		return nil, err
	}

	var out []extractedScript
	seen := make(map[string]bool)

	doc.Find("script").Each(func(_ int, sel *goquery.Selection) {
		if src, ok := sel.Attr("src"); ok {
			addLinkedScript(base, src, seen, &out)
			return
		}
		body := strings.TrimSpace(sel.Text())
		if body == "" {
			return
		}
		out = append(out, extractedScript{Inline: true, Body: body})
		if m := sourceMappingRe.FindStringSubmatch(body); m != nil {
			addLinkedScript(base, m[1], seen, &out)
		}
	})

	// Any non-script <a href> / <link href> pointing at a .js/.mjs/.cjs
	// file is also treated as a linked script candidate (bundlers/CDNs
	// commonly expose them this way too).
	doc.Find("a[href], link[href]").Each(func(_ int, sel *goquery.Selection) {
		href, _ := sel.Attr("href")
		if href == "" {
			return
		}
		u, err := base.Parse(href)
		if err != nil {
			return
		}
		if jsExtension(u.Path) {
			addLinkedScript(base, href, seen, &out)
		}
	})

	return out, nil
}

func addLinkedScript(base *url.URL, ref string, seen map[string]bool, out *[]extractedScript) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return
	}
	u, err := base.Parse(ref)
	if err != nil {
		return
	}
	u.Fragment = ""
	key := u.String()
	if seen[key] {
		return
	}
	seen[key] = true
	*out = append(*out, extractedScript{URL: u})
}

// scriptSourceMapURL extracts a sourceMappingURL reference from
// downloaded JS content, if any, resolved against the script's own
// URL.
func scriptSourceMapURL(scriptURL *url.URL, body string) *url.URL {
	m := sourceMappingRe.FindStringSubmatch(body)
	if m == nil {
		return nil
	}
	// data: URLs are inline source maps, not a fetch target.
	if strings.HasPrefix(m[1], "data:") {
		return nil
	}
	u, err := scriptURL.Parse(m[1])
	if err != nil {
		return nil
	}
	return u
}
