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
Severity:       %.1f (%s)`,
		r.Vulnerability.Severity, r.Vulnerability.SeverityLabel,
	)
	if r.Vulnerability.VulnID != "" {
		comment += fmt.Sprintf("\nVuln ID:        %s", r.Vulnerability.VulnID)
	}
	if r.Vulnerability.Package != "" {
		comment += fmt.Sprintf("\nPackage:        %s", r.Vulnerability.Package)
	}
	if r.Vulnerability.AffectedGoVersions != "" {
		comment += fmt.Sprintf("\nAffected Go:    %s", r.Vulnerability.AffectedGoVersions)
	}
	if r.Vulnerability.FixVersion != "" {
		comment += fmt.Sprintf("\nFix version:    %s", r.Vulnerability.FixVersion)
	}
	comment += fmt.Sprintf(`

Affected:       %s
Status:         %s`,
		r.Source.AffectedOperatorVersion,
		formatStatus(r.Source.Status, r.Source.Resolution),
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
	if r.Source.AffectsRHWAVersions != "" {
		comment += fmt.Sprintf("Affects:        %s\n", r.Source.AffectsRHWAVersions)
	}
	if r.Source.TicketFixVersions != "" {
		comment += fmt.Sprintf("Fix Versions:   %s\n", r.Source.TicketFixVersions)
	}

	if r.Analysis.ReleaseBranch != nil {
		comment += formatBranchSection("Release Branch", r.Analysis.ReleaseBranch, r.Recommendation.Classification)
	}
	if r.Analysis.FixUpstream != nil {
		comment += formatFixUpstreamSection(r.Analysis.FixUpstream, r.Recommendation.Classification)
	}

	if r.Vulnerability.References != "" {
		comment += fmt.Sprintf("\nReferences:     %s\n", r.Vulnerability.References)
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

	section += fmt.Sprintf("  Upstream Go:  %s\n", ba.Upstream.GoVersion)

	if ba.CatalogComponent != "" {
		section += fmt.Sprintf("  Component:    %s\n", ba.CatalogComponent)
	}

	if ba.Downstream != nil {
		if ba.Downstream.Branch != "" {
			section += fmt.Sprintf("  Downstream:   %s\n", ba.Downstream.Branch)
		}
		if ba.Downstream.GoVersion != "" {
			section += fmt.Sprintf("  Downstream Go: %s\n", ba.Downstream.GoVersion)
		}
	}

	if classification != types.Misassigned {
		section += fmt.Sprintf("  Reachability: %s\n", ba.Reachability)
		for i, cp := range ba.CallPaths {
			section += fmt.Sprintf("  Call path %d:  %s\n", i+1, cp)
		}
	}

	return section
}

func formatFixUpstreamSection(fu *types.FixUpstreamInfo, classification types.Classification) string {
	section := "\n── Fix Upstream (main) ──\n"
	section += fmt.Sprintf("  Go version:   %s\n", fu.GoVersion)

	if classification != types.Misassigned {
		section += fmt.Sprintf("  Reachability: %s\n", fu.Reachability)
		for i, cp := range fu.CallPaths {
			section += fmt.Sprintf("  Call path %d:  %s\n", i+1, cp)
		}
	}

	return section
}

func formatStatus(status, resolution string) string {
	if resolution != "" {
		return fmt.Sprintf("%s (%s)", status, resolution)
	}
	return status
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
		Operator:   r.Source.AffectedOperatorVersion,
		AssessedAt: r.AssessedAt.Format("2006-01-02T15:04:05Z"),
		Total:      1,
	}
	if r.Analysis.ReleaseBranch != nil {
		summary.CurrentGo = r.Analysis.ReleaseBranch.Upstream.GoVersion
	} else if r.Analysis.FixUpstream != nil {
		summary.CurrentGo = r.Analysis.FixUpstream.GoVersion
	}
	summary.NeededGo = r.Vulnerability.FixVersion

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
