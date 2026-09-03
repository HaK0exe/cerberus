package main

import (
	"github.com/spf13/cobra"

	webscanner "github.com/HaK0exe/cerberus/internal/scanner/web"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

func newWebCmd(flags *globalFlags) *cobra.Command {
	web := &cobra.Command{Use: "web", Short: "Web crawling and scanning"}

	var depth, maxPages, concurrency int
	var rateLimit float64
	var allowedDomains []string
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
				RespectRobots:  !ignoreRobots,
				ScanJavaScript: scanJS,
			}
			s := webscanner.New()
			_, err := s.Scan(cmd.Context(), args[0], opts)
			return err
		},
	}
	scan.Flags().IntVar(&depth, "depth", 2, "max crawl depth")
	scan.Flags().IntVar(&maxPages, "max-pages", 100, "max pages to fetch")
	scan.Flags().Float64Var(&rateLimit, "rate-limit", 2, "max requests per second")
	scan.Flags().IntVar(&concurrency, "concurrency", 4, "concurrent fetchers")
	scan.Flags().StringSliceVar(&allowedDomains, "allowed-domains", nil, "domains allowed to be crawled")
	scan.Flags().BoolVar(&ignoreRobots, "ignore-robots", false, "ignore robots.txt (explicit opt-in, prints a warning)")
	scan.Flags().BoolVar(&scanJS, "javascript", true, "download and scan linked JavaScript")

	web.AddCommand(scan)
	return web
}
