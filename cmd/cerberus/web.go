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
	var ignoreRobots, scanJS bool

	scan := &cobra.Command{
		Use:   "scan <url>",
		Short: "Crawl a website and scan pages and JavaScript for exposed secrets",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if ignoreRobots {
				cmd.PrintErrln("WARNING: robots.txt restrictions disabled")
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

			d, err := buildDetector(flags.rulesDir, nil)
			if err != nil {
				return err
			}

			s := webscanner.New()
			artifacts, err := s.Scan(cmd.Context(), args[0], opts)
			if err != nil {
				return fmt.Errorf("scanning %s: %w", args[0], err)
			}

			var all []cerberus.Finding
			for artifact := range artifacts {
				findings, err := d.Detect(cmd.Context(), artifact)
				if err != nil {
					return fmt.Errorf("scanning %s: %w", artifact.URI, err)
				}
				all = append(all, findings...)
			}

			return renderFindings(flags.format, all)
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

	web.AddCommand(scan)
	return web
}
