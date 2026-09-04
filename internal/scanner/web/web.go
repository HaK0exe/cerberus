// Package web implements a colly-based web crawler that emits
// cerberus.Artifact for HTML pages, inline scripts, and linked
// JavaScript.
//
// See crawler.go for the Crawler implementation, ssrf/ for the
// mandatory SSRF guard every outbound request routes through, and
// frontier/ for the distributed frontier (scan_id/url/depth queue +
// canonical dedup) used to fan a crawl out across multiple workers.
package web
