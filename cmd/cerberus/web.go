package main

import (
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/HaK0exe/cerberus/internal/cliui"
	webscanner "github.com/HaK0exe/cerberus/internal/scanner/web"
	"github.com/HaK0exe/cerberus/internal/scanner/web/ssrf"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func newWebCmd(flags *globalFlags) *cobra.Command {
	web := &cobra.Command{Use: "web", Short: "Web crawling and scanning"}

	var depth, maxPages, concurrency int
	var rateLimit, jitter float64
	var allowedDomains, excludePaths []string
	var ignoreRobots, scanJS, unmask, ninja bool
	var userAgent, proxy string

	scan := &cobra.Command{
		Use:     "scan <url>",
		Short:   "Crawl a website and scan pages and JavaScript for exposed secrets",
		Example: "  cerberus web scan https://example.com --depth 3 --max-pages 200\n  cerberus --offline=false web scan https://example.com --allowed-domains example.com --format json --ninja",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ui := flags.UI()
			if ninja {
				if flags.offline {
					return fmt.Errorf("--ninja requires --offline=false (web scan makes outbound network calls by design)")
				}
				if unmask {
					return fmt.Errorf("--ninja cannot be combined with --unmask (would print raw secrets to stdout)")
				}
				if flags.verbose > 0 {
					return fmt.Errorf("--ninja cannot be combined with -v/--verbose (per-request diagnostics leak crawl behavior)")
				}
				if flags.format != "json" && flags.format != "sarif" {
					return fmt.Errorf("--ninja requires --format json or sarif (got %q)", flags.format)
				}
				if len(allowedDomains) == 0 {
					return fmt.Errorf("--ninja requires --allowed-domains (never crawl allow-all in stealth)")
				}
				if cmd.Flags().Changed("concurrency") && concurrency != 1 {
					return fmt.Errorf("--ninja requires --concurrency 1 (got %d)", concurrency)
				}
				if cmd.Flags().Changed("rate-limit") && rateLimit > 1 {
					return fmt.Errorf("--ninja requires --rate-limit <= 1 (got %v)", rateLimit)
				}
				if cmd.Flags().Changed("jitter") && jitter < 1 {
					return fmt.Errorf("--ninja requires --jitter >= 1 (got %v)", jitter)
				}
				if !cmd.Flags().Changed("concurrency") {
					concurrency = 1
				}
				if !cmd.Flags().Changed("rate-limit") {
					rateLimit = 0.4
				}
				if !cmd.Flags().Changed("jitter") {
					jitter = 2.0
				}
				if !cmd.Flags().Changed("javascript") {
					scanJS = false
				}
				if !cmd.Flags().Changed("max-pages") && maxPages > 50 {
					maxPages = 50
				}
				if userAgent == "" {
					userAgent = webscanner.NinjaUserAgent()
				}
				// No robots.txt fetch in ninja mode (impolitely stealthy:
				// only acceptable against explicitly authorized targets,
				// which --allowed-domains above scopes).
				ignoreRobots = true
				// Suppress banner/progress/per-request diagnostics:
				// stdout stays pure findings JSON/SARIF.
				ui.Level = cliui.LevelQuiet
			}
			if ignoreRobots {
				ui.Warnf("robots.txt restrictions disabled")
			}
			if userAgent != "" {
				ui.Warnf("using custom User-Agent %q instead of the default self-identifying CerberusBot", userAgent)
			}
			opts := cerberus.ScanOptions{
				Depth:          depth,
				MaxPages:       maxPages,
				RateLimit:      rateLimit,
				Concurrency:    concurrency,
				AllowedDomains: allowedDomains,
				ExcludePaths:   excludePaths,
				RespectRobots:  !ignoreRobots,
				ScanJavaScript: scanJS,
				UserAgent:      userAgent,
				Jitter:         jitter,
				LowProfile:     ninja,
			}

			if ninja {
				// Fail closed: the entry URL itself must be in-scope,
				// otherwise --allowed-domains is just decoration.
				targetURL, err := url.Parse(args[0])
				if err != nil {
					return fmt.Errorf("invalid URL %q: %w", args[0], err)
				}
				scope := webscanner.Scope{AllowedDomains: allowedDomains, ExcludePaths: excludePaths}
				if !scope.Allowed(targetURL) {
					return fmt.Errorf("--ninja target %s is outside --allowed-domains", targetURL.Redacted())
				}
			}

			warnUnmask(ui, unmask)

			d, err := buildDetector(flags.rulesDir, nil, unmask)
			if err != nil {
				return err
			}

			// Per-request fetch/robots.txt failures are expected noise
			// on a real crawl (dead links, misconfigured hosts) — only
			// surface them one at a time with -vv; otherwise just tally
			// them and report a single count at the end.
			var warnCount int
			s := webscanner.New()
			s.Warnf = func(format string, args ...any) {
				warnCount++
				ui.Debugf(format, args...)
			}
			if ninja {
				// Match the TLS handshake to the chosen UA: a WAF
				// blocking on JA3 (rather than, or in addition to,
				// HTTP-level bot signals) sees a real browser's
				// ClientHello instead of Go's native one. See
				// ssrf.Guard.TLSFingerprint / ninja.go.
				s.Guard.TLSFingerprint = webscanner.NinjaTLSHello(userAgent)
			}
			if proxy != "" {
				proxyURL, err := url.Parse(proxy)
				if err != nil {
					return fmt.Errorf("invalid --proxy %q: %w", proxy, err)
				}
				if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" && proxyURL.Scheme != "socks5" {
					return fmt.Errorf("invalid --proxy %q: scheme must be http, https, or socks5", proxy)
				}
				ui.Warnf("routing every request through proxy %s — the SSRF private-range guard no longer applies to the target (the proxy resolves it, not this process)", proxyURL.Redacted())
				s.Guard = ssrf.NewGuard()
				s.Guard.ProxyURL = proxyURL
			}

			artifacts, err := s.Scan(cmd.Context(), args[0], opts)
			if err != nil {
				return fmt.Errorf("scanning %s: %w", args[0], err)
			}

			// ninja suppresses Progress (it's per-request: which URL,
			// how many so far — exactly the crawl behavior stealth
			// mode exists to not print). But total silence for the
			// run's whole multi-minute duration (concurrency 1,
			// rate-limited, up to --max-pages sequential fetches) is
			// indistinguishable from a hang. This heartbeat is the
			// deliberately content-free middle ground: proof the
			// process is alive, nothing about the target.
			//
			// stopHeartbeat is a no-op unless ninja started one, and
			// is safe to call more than once (sync.Once): called
			// explicitly before ui.DoneProgress below so the two
			// never race on ui's internal state, and deferred as a
			// backstop for any early error return in the loop.
			stopHeartbeat := func() {}
			if ninja {
				stop := make(chan struct{})
				done := make(chan struct{})
				go func() {
					defer close(done)
					ticker := time.NewTicker(15 * time.Second)
					defer ticker.Stop()
					start := time.Now()
					for {
						select {
						case <-stop:
							return
						case <-ticker.C:
							ui.Heartbeat("ninja crawl running — %s elapsed (quiet by design; findings print at the end)", time.Since(start).Round(time.Second))
						}
					}
				}()
				var once sync.Once
				stopHeartbeat = func() { once.Do(func() { close(stop); <-done }) }
			}
			defer stopHeartbeat()

			var all []cerberus.Finding
			var fetched int
			for artifact := range artifacts {
				fetched++
				ui.Progress("crawling %s — %d pages/scripts fetched, %d findings", args[0], fetched, len(all))
				findings, err := d.Detect(cmd.Context(), artifact)
				if err != nil {
					return fmt.Errorf("scanning %s: %w", artifact.URI, err)
				}
				all = append(all, findings...)
			}
			stopHeartbeat()
			ui.DoneProgress()

			if warnCount > 0 {
				ui.Warnf("%d request(s) failed during the crawl (rerun with -vv to see each one)", warnCount)
			}

			return renderFindings(ui, flags.format, all)
		},
	}
	scan.Flags().IntVar(&depth, "depth", 2, "max crawl depth")
	scan.Flags().IntVar(&maxPages, "max-pages", 100, "max pages to fetch")
	scan.Flags().Float64Var(&rateLimit, "rate-limit", 2, "max requests per second")
	scan.Flags().IntVar(&concurrency, "concurrency", 4, "concurrent fetchers")
	scan.Flags().StringSliceVar(&allowedDomains, "allowed-domains", nil, "domains allowed to be crawled")
	scan.Flags().StringSliceVar(&excludePaths, "exclude-path", nil, "path prefixes to exclude from the crawl")
	scan.Flags().BoolVar(&ignoreRobots, "ignore-robots", false, "ignore robots.txt (explicit opt-in, prints a warning)")
	scan.Flags().BoolVar(&scanJS, "javascript", true, "download and scan linked JavaScript")
	scan.Flags().StringVar(&userAgent, "user-agent", "", "custom User-Agent (default CerberusBot)")
	scan.Flags().StringVar(&proxy, "proxy", "", "proxy URL for all requests (http, https, or socks5, direct if empty)")
	scan.Flags().Float64Var(&jitter, "jitter", 0, "max extra random delay in seconds between requests")
	scan.Flags().BoolVar(&ninja, "ninja", false, "low-profile crawl: browser UA + matching TLS (JA3) fingerprint, slow irregular cadence, no robots.txt (requires --offline=false, --allowed-domains, --format json|sarif)")
	scan.Flags().BoolVar(&unmask, "unmask", false, "print full secret values instead of a masked hint (local triage only — never use in CI/logs)")

	web.AddCommand(scan)
	return web
}
