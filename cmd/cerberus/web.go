package main

import (
	"fmt"

	"github.com/spf13/cobra"

	webscanner "github.com/HaK0exe/cerberus/internal/scanner/web"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func newWebCmd(flags *globalFlags) *cobra.Command {
	web := &cobra.Command{Use: "web", Short: "Web crawling and scanning"}

	var depth, maxPages, concurrency int
	var rateLimit float64
	var allowedDomains, excludePaths []string
	var ignoreRobots, scanJS, unmask bool

	scan := &cobra.Command{
		Use:     "scan <url>",
		Short:   "Crawl a website and scan pages and JavaScript for exposed secrets",
		Example: "  cerberus web scan https://example.com --depth 3 --max-pages 200",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ui := flags.UI()
			if ignoreRobots {
				ui.Warnf("robots.txt restrictions disabled")
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

			artifacts, err := s.Scan(cmd.Context(), args[0], opts)
			if err != nil {
				return fmt.Errorf("scanning %s: %w", args[0], err)
			}

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
	scan.Flags().BoolVar(&unmask, "unmask", false, "print full secret values instead of a masked hint (local triage only — never use in CI/logs)")

	web.AddCommand(scan)
	return web
}
