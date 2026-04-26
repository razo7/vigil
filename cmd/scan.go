package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/razo7/vigil/pkg/assess"
	"github.com/razo7/vigil/pkg/jira"
	"github.com/razo7/vigil/pkg/report"
	"github.com/razo7/vigil/pkg/types"
	"github.com/spf13/cobra"
)

var (
	scanComponent     string
	scanJQL           string
	scanJira          bool
	scanSummaryFile   string
	scanRepoPath      string
	scanIncludeClosed bool
)

var componentJQLMap = map[string]string{
	"far": `project in (RHWA, ECOPROJECT) AND issuetype in (Vulnerability, Bug) AND component in ("Fence Agents Remediation") AND status not in (Closed) ORDER BY created DESC`,
	"snr": `project in (RHWA, ECOPROJECT) AND issuetype in (Vulnerability, Bug) AND component in ("Self Node Remediation") AND status not in (Closed) ORDER BY created DESC`,
	"nhc": `project in (RHWA, ECOPROJECT) AND issuetype in (Vulnerability, Bug) AND component in ("Node Healthcheck Controller") AND status not in (Closed) ORDER BY created DESC`,
	"nmo": `project in (RHWA, ECOPROJECT) AND issuetype in (Vulnerability, Bug) AND component in ("Node Maintenance Operator") AND status not in (Closed) ORDER BY created DESC`,
	"mdr": `project in (RHWA, ECOPROJECT) AND issuetype in (Vulnerability, Bug) AND component in ("Machine Deletion Remediation") AND status not in (Closed) ORDER BY created DESC`,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Batch assess all CVE tickets for a component",
	Long: `Find all open CVE tickets for the specified component via JQL query,
then assess each one.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if scanComponent == "" && scanJQL == "" {
			return fmt.Errorf("either --component or --jql is required")
		}

		jql := scanJQL
		if jql == "" {
			key := strings.ToLower(scanComponent)
			var ok bool
			jql, ok = componentJQLMap[key]
			if !ok {
				return fmt.Errorf("unknown component %q; use --jql for custom queries", scanComponent)
			}
			if scanIncludeClosed {
				jql = strings.Replace(jql, " AND status not in (Closed)", "", 1)
			}
		}

		jiraClient, err := jira.NewClient()
		if err != nil {
			return fmt.Errorf("creating Jira client: %w", err)
		}

		tickets, err := jiraClient.SearchTickets(jql)
		if err != nil {
			return fmt.Errorf("searching tickets: %w", err)
		}

		if len(tickets) == 0 {
			fmt.Println("No CVE tickets found.")
			return nil
		}

		fmt.Fprintf(os.Stderr, "Found %d CVE tickets. Assessing...\n", len(tickets))

		ctx := context.Background()
		var results []*types.Result
		var errors []string

		for i, ticket := range tickets {
			ticketID := ticket.Key
			if ticketID == "" {
				continue
			}

			fmt.Fprintf(os.Stderr, "[%d/%d] %s ", i+1, len(tickets), ticketID)

			result, err := assess.Run(ctx, assess.Options{
				TicketID: ticketID,
				RepoPath: scanRepoPath,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
				errors = append(errors, fmt.Sprintf("%s: %v", ticketID, err))
				continue
			}

			results = append(results, result)
			fmt.Fprintf(os.Stderr, "→ %s (%s)\n", result.Recommendation.Classification, result.Recommendation.Priority)

			if scanJira {
				if err := report.PostToJira(result); err != nil {
					fmt.Fprintf(os.Stderr, "  WARNING: failed to post Jira comment: %v\n", err)
				}
			}
		}

		output := map[string]interface{}{
			"total":    len(tickets),
			"assessed": len(results),
			"errors":   len(errors),
			"results":  results,
		}

		if err := printJSON(output); err != nil {
			return fmt.Errorf("marshaling output: %w", err)
		}

		if scanSummaryFile != "" {
			if err := writeBatchSummary(scanSummaryFile, results); err != nil {
				return fmt.Errorf("writing summary: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Summary written to %s\n", scanSummaryFile)
		}

		return nil
	},
}

func writeBatchSummary(path string, results []*types.Result) error {
	summary := report.SanitizedSummary{
		Total: len(results),
	}

	if len(results) > 0 {
		summary.Operator = results[0].Source.Operator
		summary.AssessedAt = results[0].AssessedAt.Format("2006-01-02T15:04:05Z")
		if ba := primaryBranch(results[0]); ba != nil {
			summary.CurrentGo = ba.Upstream.GoVersion
		}
	}

	var neededGo string
	for _, r := range results {
		switch r.Recommendation.Classification {
		case types.FixableNow:
			summary.FixableNow++
		case types.BlockedByGo:
			summary.BlockedByGo++
		case types.NotReachable:
			summary.NotReachable++
		case types.NotGo:
			summary.NotGo++
		case types.Misassigned:
			summary.Misassigned++
		}
		if ba := primaryBranch(r); ba != nil && ba.FixVersion != "" {
			if neededGo == "" || ba.FixVersion > neededGo {
				neededGo = ba.FixVersion
			}
		}
	}
	summary.NeededGo = neededGo

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func primaryBranch(r *types.Result) *types.BranchAnalysis {
	if r.Analysis.ReleaseBranch != nil {
		return r.Analysis.ReleaseBranch
	}
	return r.Analysis.LatestBranch
}

func init() {
	scanCmd.Flags().StringVar(&scanComponent, "component", "", "Component name (e.g., FAR, SNR, NHC, NMO, MDR)")
	scanCmd.Flags().StringVar(&scanJQL, "jql", "", "Custom JQL query")
	scanCmd.Flags().BoolVar(&scanJira, "jira", false, "Post assessments as Jira comments")
	scanCmd.Flags().StringVar(&scanSummaryFile, "summary-file", "", "Write aggregate summary to file")
	scanCmd.Flags().StringVar(&scanRepoPath, "repo-path", "", "Path to operator repo (auto-detected from Jira component if omitted)")
	scanCmd.Flags().BoolVar(&scanIncludeClosed, "include-closed", false, "Include closed tickets (historical reference)")
	rootCmd.AddCommand(scanCmd)
}
