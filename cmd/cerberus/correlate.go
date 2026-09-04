package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/HaK0exe/cerberus/internal/credentials"
	"github.com/HaK0exe/cerberus/internal/intelligence"
	intelaws "github.com/HaK0exe/cerberus/internal/intelligence/aws"
	"github.com/HaK0exe/cerberus/internal/risk"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// newCorrelateCmd wires the Credential/Exposure/Incident correlation
// service: given a set of Findings (e.g. from `scan file --format
// json`, `git scan --format json`), it groups occurrences of the same
// secret — matched by HMAC fingerprint — into Credentials, one Exposure
// per distinct location, and one Incident per Credential, then runs
// each Credential through the risk engine (internal/risk.Assess) and
// the offline credential-intelligence registry (internal/intelligence)
// so the output is triage-ready, not just deduplicated.
//
// TODO(sprint-4): once the API/storage layer exists, correlation runs
// continuously against the Finding store instead of a one-shot file;
// `credentials`/`incidents` list/get will read from that store.
func newCorrelateCmd(flags *globalFlags) *cobra.Command {
	var input string
	var withRisk bool
	var withEnrich bool

	cmd := &cobra.Command{
		Use:   "correlate",
		Short: "Correlate findings into credentials, exposures, incidents, risk, and intelligence",
		Long: "Reads a Findings JSON array (from --input or stdin) and groups\n" +
			"findings that share an HMAC fingerprint into Credentials, Exposures,\n" +
			"and Incidents, so the same secret found in multiple places is\n" +
			"reported once instead of as independent findings. Each Credential is\n" +
			"then risk-assessed (internal/risk) and offline-enriched\n" +
			"(internal/intelligence) unless disabled with --risk=false/--enrich=false.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var r io.Reader = os.Stdin
			if input != "" && input != "-" {
				f, err := os.Open(input) // #nosec G304 -- input is a --input path supplied on the CLI command line
				if err != nil {
					return fmt.Errorf("opening %s: %w", input, err)
				}
				defer f.Close()
				r = f
			}

			var findings []cerberus.Finding
			if err := json.NewDecoder(r).Decode(&findings); err != nil {
				return fmt.Errorf("decoding findings JSON: %w", err)
			}

			creds, exposures, incidents := credentials.Correlate(findings)

			var risks map[string]cerberus.RiskAssessment
			if withRisk {
				risks = assessRisk(creds, exposures)
			}

			var enrichments map[string][]cerberus.Enrichment
			if withEnrich {
				enrichments = enrichCredentials(cmd.Context(), creds)
			}

			return renderCorrelation(flags.format, creds, exposures, incidents, risks, enrichments)
		},
	}

	cmd.Flags().StringVar(&input, "input", "-", "path to a Findings JSON file (default: stdin)")
	cmd.Flags().BoolVar(&withRisk, "risk", true, "assess risk for each credential (internal/risk)")
	cmd.Flags().BoolVar(&withEnrich, "enrich", true, "run offline credential intelligence enrichers (internal/intelligence)")
	return cmd
}

// assessRisk runs internal/risk.Assess for every credential against its
// own exposures. Pure and offline — see internal/risk/risk.go.
func assessRisk(creds []cerberus.Credential, exposures []cerberus.Exposure) map[string]cerberus.RiskAssessment {
	expByCred := groupExposuresByCredential(exposures)
	out := make(map[string]cerberus.RiskAssessment, len(creds))
	for _, c := range creds {
		out[c.ID] = risk.Assess(c, expByCred[c.ID])
	}
	return out
}

// enrichCredentials runs the intelligence.Registry (currently: an
// offline AWS structural enricher, internal/intelligence/aws) against
// every credential. Enrichment failures are logged to stderr and
// otherwise ignored — offline enrichment failing must never fail the
// whole correlate run, and never fabricates a result for a credential
// no enricher supports.
func enrichCredentials(ctx context.Context, creds []cerberus.Credential) map[string][]cerberus.Enrichment {
	reg := intelligence.NewRegistry(intelaws.New())
	out := make(map[string][]cerberus.Enrichment, len(creds))
	for _, c := range creds {
		results, err := reg.EnrichAll(ctx, c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: enriching credential %s: %v\n", c.ID, err)
		}
		if len(results) > 0 {
			out[c.ID] = results
		}
	}
	return out
}

func groupExposuresByCredential(exposures []cerberus.Exposure) map[string][]cerberus.Exposure {
	byCred := make(map[string][]cerberus.Exposure)
	for _, e := range exposures {
		byCred[e.CredentialID] = append(byCred[e.CredentialID], e)
	}
	return byCred
}

type correlationResult struct {
	Credentials []cerberus.Credential `json:"credentials"`
	Exposures   []cerberus.Exposure   `json:"exposures"`
	Incidents   []cerberus.Incident   `json:"incidents"`

	// Risk and Enrichments are keyed by Credential.ID. Both are omitted
	// entirely (nil map) when their corresponding --risk/--enrich flag
	// was disabled, rather than emitted empty — an absent key means
	// "not computed", never "computed and found nothing".
	Risk        map[string]cerberus.RiskAssessment `json:"risk,omitempty"`
	Enrichments map[string][]cerberus.Enrichment   `json:"enrichments,omitempty"`
}

func renderCorrelation(
	format string,
	creds []cerberus.Credential,
	exposures []cerberus.Exposure,
	incidents []cerberus.Incident,
	risks map[string]cerberus.RiskAssessment,
	enrichments map[string][]cerberus.Enrichment,
) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(correlationResult{
			Credentials: creds,
			Exposures:   exposures,
			Incidents:   incidents,
			Risk:        risks,
			Enrichments: enrichments,
		})
	case "text", "":
		if len(creds) == 0 {
			fmt.Println("no credentials")
			return nil
		}
		expByCred := groupExposuresByCredential(exposures)
		for _, c := range creds {
			fmt.Printf("%s  %s/%s  exposures=%d  first_seen=%s%s\n",
				c.ID, c.Provider, c.Kind, c.ExposureCount, c.FirstSeen.Format("2006-01-02"),
				riskSuffix(risks, c.ID))
			for _, e := range expByCred[c.ID] {
				fmt.Printf("    - %s%s\n", e.Path, commitSuffix(e.Commit))
			}
			for _, en := range enrichments[c.ID] {
				fmt.Printf("    * %s: %v\n", en.Source, en.Attributes)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown format %q (want json|text)", format)
	}
}

func riskSuffix(risks map[string]cerberus.RiskAssessment, credentialID string) string {
	r, ok := risks[credentialID]
	if !ok {
		return ""
	}
	return fmt.Sprintf("  risk=%s(%.2f)", r.Level, r.Score)
}
