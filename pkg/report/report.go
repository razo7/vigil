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
Ticket:         %s
CVE:            %s`,
		r.Source.TicketID,
		r.Vulnerability.CVEID,
	)
	if r.Vulnerability.CWE != "" {
		cwe := r.Vulnerability.CWE
		if r.Vulnerability.CWEDescription != "" {
			cwe += " — " + r.Vulnerability.CWEDescription
		}
		comment += fmt.Sprintf(`
CWE:            %s`, cwe)
	}
	comment += fmt.Sprintf(`
Severity:       %.1f (%s)

Operator:       %s %s`,
		r.Vulnerability.Severity, r.Vulnerability.SeverityLabel,
		r.Source.Operator, r.Source.OperatorVersion,
	)

	if len(r.Source.OCPSupport) > 0 {
		comment += "\nOCP Support:"
		for _, e := range r.Source.OCPSupport {
			comment += fmt.Sprintf("\n  %s", e)
		}
	}
	comment += "\n"

	if r.Source.Reporter != "" || r.Source.Assignee != "" {
		comment += "\n"
		if r.Source.Reporter != "" {
			comment += fmt.Sprintf("Reporter:       %s\n", r.Source.Reporter)
		}
		if r.Source.Assignee != "" {
			comment += fmt.Sprintf("Assignee:       %s\n", r.Source.Assignee)
		}
		if r.Source.DueDate != "" {
			comment += fmt.Sprintf("Due Date:       %s\n", r.Source.DueDate)
		}
		if r.Source.JiraPriority != "" {
			comment += fmt.Sprintf("Jira Priority:  %s\n", r.Source.JiraPriority)
		}
	}
	if r.Source.Labels != "" {
		comment += fmt.Sprintf("Labels:         %s\n", r.Source.Labels)
	}
	if r.Source.AffectsVersions != "" {
		comment += fmt.Sprintf("Affects:        %s\n", r.Source.AffectsVersions)
	}
	if r.Source.TicketFixVersions != "" {
		comment += fmt.Sprintf("Fix Versions:   %s\n", r.Source.TicketFixVersions)
	}

	if r.Analysis.ReleaseBranch != nil {
		comment += formatBranchSection("Release Branch", r.Analysis.ReleaseBranch, r.Recommendation.Classification)
	}
	if r.Analysis.LatestBranch != nil {
		comment += formatBranchSection("Latest Branch", r.Analysis.LatestBranch, r.Recommendation.Classification)
	}

	if len(r.Vulnerability.References) > 0 {
		comment += "\nReferences:\n"
		for _, ref := range r.Vulnerability.References {
			comment += fmt.Sprintf("  - %s\n", ref)
		}
	}

	comment += fmt.Sprintf(`
Classification: %s
Priority:       %s`+"\n", r.Recommendation.Classification, r.Recommendation.Priority)

	comment += fmt.Sprintf(`
Recommendation:
  %s

Assessed: %s by Vigil %s
──────────────────────────────────────────`,
		r.Recommendation.Action,
		r.AssessedAt.Format("2006-01-02"),
		r.Version,
	)

	return comment
}

func formatBranchSection(label string, ba *types.BranchAnalysis, classification types.Classification) string {
	section := fmt.Sprintf("\n── %s: %s ──\n", label, ba.Upstream.Branch)

	section += fmt.Sprintf("  Upstream Go:  %s", ba.Upstream.GoVersion)
	if ba.Upstream.GoModLink != "" {
		section += fmt.Sprintf(" (%s)", ba.Upstream.GoModLink)
	}
	section += "\n"

	if ba.Downstream != nil {
		if ba.Downstream.GoVersion != "" {
			section += fmt.Sprintf("  Downstream Go: %s", ba.Downstream.GoVersion)
			if ba.Downstream.GoLink != "" {
				section += fmt.Sprintf(" (%s)", ba.Downstream.GoLink)
			}
			section += "\n"
		}
		if ba.Downstream.ComponentName != "" {
			section += fmt.Sprintf("  Component:    %s (%s)\n", ba.Downstream.ComponentName, ba.Downstream.RHELBase)
			if ba.Downstream.ComponentURL != "" {
				section += fmt.Sprintf("                %s\n", ba.Downstream.ComponentURL)
			}
		}
	}

	if ba.VulnID != "" {
		section += fmt.Sprintf("  Vuln ID:      %s\n", ba.VulnID)
	}
	if ba.Package != "" {
		section += fmt.Sprintf("  Package:      %s\n", ba.Package)
	}
	if ba.AffectedGoVersions != "" {
		section += fmt.Sprintf("  Affected Go:  %s\n", ba.AffectedGoVersions)
	}
	if ba.FixVersion != "" {
		section += fmt.Sprintf("  Fix version:  %s\n", ba.FixVersion)
	}

	if classification != types.Misassigned {
		section += fmt.Sprintf("  Reachability: %s\n", ba.Reachability)
		if ba.CallPath != "" {
			section += fmt.Sprintf("  Call path:    %s\n", ba.CallPath)
		}
	}

	return section
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
	ba := r.Analysis.ReleaseBranch
	if ba == nil {
		ba = r.Analysis.LatestBranch
	}

	summary := SanitizedSummary{
		Operator:   r.Source.Operator,
		AssessedAt: r.AssessedAt.Format("2006-01-02T15:04:05Z"),
		Total:      1,
	}
	if ba != nil {
		summary.CurrentGo = ba.Upstream.GoVersion
		summary.NeededGo = ba.FixVersion
	}

	switch r.Recommendation.Classification {
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
	return client.PostComment(r.Source.TicketID, comment)
}
