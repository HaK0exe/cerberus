// Package sarif renders cerberus.Finding slices as SARIF 2.1.0
// (https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
// for consumption by code-scanning tools (e.g. GitHub code scanning).
//
// Rendering never includes a raw secret value — only what
// cerberus.Finding already carries (masked prefix, fingerprint,
// location).
package sarif

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

const schemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
const sarifVersion = "2.1.0"

type log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri,omitempty"`
	Version        string `json:"version,omitempty"`
	Rules          []rule `json:"rules"`
}

type rule struct {
	ID string `json:"id"`
}

type result struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Message    message           `json:"message"`
	Locations  []location        `json:"locations"`
	Properties map[string]string `json:"properties,omitempty"`
}

type message struct {
	Text string `json:"text"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

// Write renders findings as a SARIF 2.1.0 log to w.
func Write(w io.Writer, findings []cerberus.Finding, toolName, toolVersion string) error {
	ruleIDs := map[string]struct{}{}
	results := make([]result, 0, len(findings))

	for _, f := range findings {
		ruleIDs[f.RuleID] = struct{}{}

		props := map[string]string{
			"fingerprint": f.Fingerprint,
			"maskedValue": f.MaskedPrefix,
		}
		if f.Commit != "" {
			props["commit"] = f.Commit
		}

		results = append(results, result{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: message{Text: "Potential " + f.Type + " detected (masked: " + f.MaskedPrefix + ")"},
			Locations: []location{{
				PhysicalLocation: physicalLocation{
					ArtifactLocation: artifactLocation{URI: f.Path},
				},
			}},
			Properties: props,
		})
	}

	rules := make([]rule, 0, len(ruleIDs))
	for id := range ruleIDs {
		rules = append(rules, rule{ID: id})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	l := log{
		Schema:  schemaURI,
		Version: sarifVersion,
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           toolName,
				InformationURI: "https://github.com/HaK0exe/cerberus",
				Version:        toolVersion,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(l)
}

func sarifLevel(sev cerberus.Severity) string {
	switch sev {
	case cerberus.SeverityCritical, cerberus.SeverityHigh:
		return "error"
	case cerberus.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
