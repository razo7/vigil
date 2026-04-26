package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/razo7/vigil/pkg/jira"
	"github.com/razo7/vigil/pkg/types"
)

func FormatJiraComment(r *types.Result) string {
	comment := fmt.Sprintf(`── Vigil Assessment ──────────────────────
CVE:            %s
Source:         %s
Severity:       %.1f (%s)
Package:        %s
Classification: %s
Priority:       %s

Operator:       %s
OCP Version:    %s
Support Phase:  %s
`,
		r.CVEID,
		r.CVESource,
		r.Severity, r.SeverityLabel,
		r.Package,
		r.Classification,
		r.Priority,
		r.OperatorVersion,
		r.OCPVersion,
		r.SupportPhase,
	)

	if r.Classification == types.Misassigned {
		comment += fmt.Sprintf(`
Misassignment:  %s
`, r.MisassignReason)
	} else {
		comment += fmt.Sprintf(`
govulncheck:    %s`, r.Reachability)
		if r.VulnID != "" {
			comment += fmt.Sprintf(` (%s)`, r.VulnID)
		}
		comment += fmt.Sprintf(`
  Fix version:  %s
  Current:      %s (toolchain in go.mod)
  Downstream:   %s
`, r.FixVersion, r.CurrentGo, r.DownstreamGo)

		if r.CallPath != "" {
			comment += fmt.Sprintf(`
Call path:
  %s
`, r.CallPath)
		}
	}

	comment += fmt.Sprintf(`
Recommendation:
  %s

Assessed: %s by Vigil %s
──────────────────────────────────────────`,
		r.Recommendation,
		r.AssessedAt.Format("2006-01-02"),
		r.Version,
	)

	return comment
}

type SanitizedSummary struct {
	Operator     string `json:"operator"`
	AssessedAt   string `json:"assessed_at"`
	Total        int    `json:"total"`
	FixableNow   int    `json:"fixable_now"`
	BlockedByGo  int    `json:"blocked_by_go"`
	NotReachable int    `json:"not_reachable"`
	NotGo        int    `json:"not_go"`
	Misassigned  int    `json:"misassigned"`
	CurrentGo    string `json:"current_go"`
	NeededGo     string `json:"needed_go"`
}

func WriteSanitizedSummary(path string, r *types.Result) error {
	summary := SanitizedSummary{
		Operator:   r.Operator,
		AssessedAt: r.AssessedAt.Format("2006-01-02T15:04:05Z"),
		Total:      1,
		CurrentGo:  r.CurrentGo,
		NeededGo:   r.FixVersion,
	}

	switch r.Classification {
	case types.FixableNow:
		summary.FixableNow = 1
	case types.BlockedByGo:
		summary.BlockedByGo = 1
	case types.NotReachable:
		summary.NotReachable = 1
	case types.NotGo:
		summary.NotGo = 1
	case types.Misassigned:
		summary.Misassigned = 1
	}

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling summary: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

func PostToJira(r *types.Result) error {
	client, err := jira.NewClient()
	if err != nil {
		return fmt.Errorf("creating Jira client: %w", err)
	}
	comment := FormatJiraComment(r)
	return client.PostComment(r.TicketID, comment)
}
