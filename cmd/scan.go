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
	"golang.org/x/term"
)

var (
	scanComponent     string
	scanJQL           string
	scanJira          bool
	scanSummaryFile   string
	scanRepoPath      string
	scanIncludeClosed bool
	scanShort         bool
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

		tickets, err := jira.SearchTicketsCLI(jql)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: jira CLI search failed (%v), falling back to REST API\n", err)
			jiraClient, clientErr := jira.NewClient()
			if clientErr != nil {
				return fmt.Errorf("creating Jira client: %w", clientErr)
			}
			tickets, err = jiraClient.SearchTickets(jql)
			if err != nil {
				return fmt.Errorf("searching tickets: %w", err)
			}
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

			ticketLink := termLink(ticketID, fmt.Sprintf("https://redhat.atlassian.net/browse/%s", ticketID))
			fmt.Fprintf(os.Stderr, "[%d/%d] %s ", i+1, len(tickets), ticketLink)

			if ticket.CVEID == "" {
				fmt.Fprintf(os.Stderr, "no CVE ID (SKIP). Ticket is about: %s\n", ticket.Summary)
				continue
			}

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

		if scanShort {
			printScanTable(results, errors)
		} else {
			output := map[string]interface{}{
				"total":    len(tickets),
				"assessed": len(results),
				"errors":   len(errors),
				"results":  results,
			}
			if err := printJSON(output); err != nil {
				return fmt.Errorf("marshaling output: %w", err)
			}
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
		summary.Operator = results[0].Source.AffectedOperatorVersion
		summary.AssessedAt = results[0].AssessedAt.Format("2006-01-02T15:04:05Z")
		if ba := results[0].Analysis.ReleaseBranch; ba != nil {
			summary.CurrentGo = ba.Upstream.GoVersion
		} else if fu := results[0].Analysis.FixUpstream; fu != nil {
			summary.CurrentGo = fu.GoVersion
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
		if r.Vulnerability.FixVersion != "" {
			if neededGo == "" || r.Vulnerability.FixVersion > neededGo {
				neededGo = r.Vulnerability.FixVersion
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

func printScanTable(results []*types.Result, errors []string) {
	isTTY := forceColor || term.IsTerminal(int(os.Stdout.Fd()))

	headerFmt := "%-18s %-16s %-8s %-4s %-18s %-16s %-14s %5s %-14s %s\n"
	rowFmt := "%-18s %-16s %-8s %-4s %-18s %-16s %-14s %5.1f %-14s %s\n"
	lineWidth := 140

	if isTTY {
		fmt.Printf("\033[1m"+headerFmt+colorReset,
			"TICKET", "CVE", "VERSION", "LANG", "STATUS", "CLASSIFICATION", "PRIORITY", "CVSS", "REACHABILITY", "PACKAGE")
		fmt.Println(strings.Repeat("─", lineWidth))
	} else {
		fmt.Printf(headerFmt,
			"TICKET", "CVE", "VERSION", "LANG", "STATUS", "CLASSIFICATION", "PRIORITY", "CVSS", "REACHABILITY", "PACKAGE")
		fmt.Println(strings.Repeat("-", lineWidth))
	}

	counts := map[types.Classification]int{}
	for _, r := range results {
		ticket := extractTicketID(r.Source.TicketID)
		ticketURL := extractTicketURL(r.Source.TicketID)
		cveID := shortCVEID(r.Vulnerability.CVEID)
		version := extractVersion(r.Source.AffectedOperatorVersion)
		lang := shortLanguage(r.Vulnerability.Language)
		status := shortStatus(r.Source.Status, r.Source.Resolution)
		class := string(r.Recommendation.Classification)
		priority := shortPriority(r.Recommendation.Priority)
		cvss := r.Vulnerability.Severity
		reach := shortReachability(r)
		pkg := shortPackage(r.Vulnerability.Package)

		counts[r.Recommendation.Classification]++

		if isTTY {
			ticketDisplay := termLink(fmt.Sprintf("%-18s", ticket), ticketURL)
			cveDisplay := termLink(fmt.Sprintf("%-16s", cveID), extractCVEURL(r.Vulnerability.CVEID))
			classColor := colorForClassification(r.Recommendation.Classification)
			prioColor := colorForPriority(r.Recommendation.Priority)
			statusColor := colorForStatus(r.Source.Status)
			fmt.Printf("%s %s %-8s %-4s %s%-18s%s %s%-16s%s %s%-14s%s %5.1f %-14s %s\n",
				ticketDisplay, cveDisplay, version, lang,
				statusColor, status, colorReset,
				classColor, class, colorReset,
				prioColor, priority, colorReset,
				cvss, reach, pkg)
		} else {
			fmt.Printf(rowFmt, ticket, cveID, version, lang, status, class, priority, cvss, reach, pkg)
		}
	}

	if isTTY {
		fmt.Println(strings.Repeat("─", lineWidth))
	} else {
		fmt.Println(strings.Repeat("-", lineWidth))
	}

	var summary []string
	summary = append(summary, fmt.Sprintf("%d assessed", len(results)))
	if n := counts[types.FixableNow]; n > 0 {
		summary = append(summary, fmt.Sprintf("%d fixable", n))
	}
	if n := counts[types.BlockedByGo]; n > 0 {
		summary = append(summary, fmt.Sprintf("%d blocked", n))
	}
	if n := counts[types.NotReachable]; n > 0 {
		summary = append(summary, fmt.Sprintf("%d not-reachable", n))
	}
	if n := counts[types.NotGo]; n > 0 {
		summary = append(summary, fmt.Sprintf("%d not-go", n))
	}
	if n := counts[types.Misassigned]; n > 0 {
		summary = append(summary, fmt.Sprintf("%d misassigned", n))
	}
	if len(errors) > 0 {
		summary = append(summary, fmt.Sprintf("%d errors", len(errors)))
	}
	fmt.Println(strings.Join(summary, ", "))
}

func extractTicketID(s string) string {
	if i := strings.Index(s, " "); i > 0 {
		return s[:i]
	}
	return s
}

func extractTicketURL(s string) string {
	if start := strings.Index(s, "("); start >= 0 {
		if end := strings.Index(s[start:], ")"); end >= 0 {
			return s[start+1 : start+end]
		}
	}
	return ""
}

func termLink(text, url string) string {
	if url == "" {
		return text
	}
	return fmt.Sprintf("\033]8;;%s\033\\%s\033]8;;\033\\", url, text)
}

func shortCVEID(s string) string {
	if i := strings.Index(s, " "); i > 0 {
		return s[:i]
	}
	return s
}

func extractCVEURL(s string) string {
	if start := strings.Index(s, "("); start >= 0 {
		if end := strings.Index(s[start:], ")"); end >= 0 {
			return s[start+1 : start+end]
		}
	}
	return ""
}

func shortLanguage(lang string) string {
	switch lang {
	case "Golang":
		return "Go"
	case "Python":
		return "Py"
	case "JavaScript":
		return "JS"
	case "Ruby":
		return "Rb"
	case "Java":
		return "Jv"
	case "C":
		return "C"
	case "PHP":
		return "PHP"
	case "Perl":
		return "Pl"
	default:
		return "?"
	}
}

func extractVersion(s string) string {
	if i := strings.Index(s, ":"); i >= 0 {
		return s[i+1:]
	}
	return ""
}

func shortStatus(status, resolution string) string {
	if resolution != "" {
		return fmt.Sprintf("%s (%s)", status, resolution)
	}
	return status
}

func colorForStatus(status string) string {
	switch status {
	case "Closed":
		return colorNull
	case "New", "To Do":
		return colorString
	default:
		return colorCyanBold
	}
}

func shortPriority(p types.Priority) string {
	if p == types.PriorityManual {
		return "Manual"
	}
	return string(p)
}

func shortReachability(r *types.Result) string {
	if ba := r.Analysis.ReleaseBranch; ba != nil {
		return firstWord(ba.Reachability)
	}
	if fu := r.Analysis.FixUpstream; fu != nil {
		return firstWord(fu.Reachability)
	}
	return "N/A"
}

func firstWord(s string) string {
	if i := strings.IndexByte(s, ' '); i > 0 {
		return s[:i]
	}
	return s
}

func shortPackage(pkg string) string {
	if i := strings.Index(pkg, " ("); i > 0 {
		pkg = pkg[:i]
	}
	if len(pkg) > 30 {
		return pkg[:27] + "..."
	}
	return pkg
}

func colorForClassification(c types.Classification) string {
	switch c {
	case types.FixableNow:
		return colorLow
	case types.BlockedByGo:
		return colorHigh
	case types.NotReachable:
		return colorLow
	case types.NotGo:
		return colorMed
	case types.Misassigned:
		return colorNull
	default:
		return colorString
	}
}

func colorForPriority(p types.Priority) string {
	switch p {
	case types.PriorityCritical:
		return colorCrit
	case types.PriorityHigh:
		return colorHigh
	case types.PriorityMedium:
		return colorMed
	case types.PriorityLow:
		return colorLow
	default:
		return colorNull
	}
}

func init() {
	scanCmd.Flags().StringVar(&scanComponent, "component", "", "Component name (e.g., FAR, SNR, NHC, NMO, MDR)")
	scanCmd.Flags().StringVar(&scanJQL, "jql", "", "Custom JQL query")
	scanCmd.Flags().BoolVar(&scanJira, "jira", false, "Post assessments as Jira comments")
	scanCmd.Flags().StringVar(&scanSummaryFile, "summary-file", "", "Write aggregate summary to file")
	scanCmd.Flags().StringVar(&scanRepoPath, "repo-path", "", "Path to operator repo (auto-detected from Jira component if omitted)")
	scanCmd.Flags().BoolVar(&scanIncludeClosed, "include-closed", false, "Include closed tickets (historical reference)")
	scanCmd.Flags().BoolVar(&scanShort, "short", false, "Print compact summary table instead of full JSON")
	rootCmd.AddCommand(scanCmd)
}
