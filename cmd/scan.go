package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/razo7/vigil/pkg/assess"
	"github.com/razo7/vigil/pkg/discover"
	"github.com/razo7/vigil/pkg/fix"
	"github.com/razo7/vigil/pkg/jira"
	"github.com/razo7/vigil/pkg/report"
	"github.com/razo7/vigil/pkg/trivy"
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
	scanDiscover      bool
	scanSince         string
	scanTrivy         bool
	scanFix           bool
)

var componentJQLMap = map[string]string{
	"far": `project in (RHWA, ECOPROJECT) AND issuetype in (Vulnerability, Bug) AND component in ("Fence Agents Remediation") AND status not in (Closed) ORDER BY created DESC`,
	"snr": `project in (RHWA, ECOPROJECT) AND issuetype in (Vulnerability, Bug) AND component in ("Self Node Remediation") AND status not in (Closed) ORDER BY created DESC`,
	"nhc": `project in (RHWA, ECOPROJECT) AND issuetype in (Vulnerability, Bug) AND component in ("Node Healthcheck") AND status not in (Closed) ORDER BY created DESC`,
	"nmo": `project in (RHWA, ECOPROJECT) AND issuetype in (Vulnerability, Bug) AND component in ("Node Maintenance Operator") AND status not in (Closed) ORDER BY created DESC`,
	"mdr": `project in (RHWA, ECOPROJECT) AND issuetype in (Vulnerability, Bug) AND component in ("Machine Deletion Remediation") AND status not in (Closed) ORDER BY created DESC`,
	"sbr":         `project in (RHWA, ECOPROJECT) AND issuetype in (Vulnerability, Bug) AND component in ("Storage-based Remediation") AND status not in (Closed) ORDER BY created DESC`,
	"nhc-console": `project in (RHWA, ECOPROJECT) AND issuetype in (Vulnerability, Bug) AND component in ("Node Remediation Console") AND status not in (Closed) ORDER BY created DESC`,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Batch assess all CVE tickets for a component",
	Long: `Find all open CVE tickets for the specified component via JQL query,
then assess each one. By default, also runs govulncheck to discover
vulnerabilities that may not have Jira tickets yet.

Use --discover to run govulncheck + Trivy discovery without Jira assessment.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if scanComponent == "" && scanJQL == "" {
			return fmt.Errorf("either --component or --jql is required")
		}

		if scanDiscover {
			return runDiscoverOnly()
		}

		return runCombinedScan()
	},
}

func runDiscoverOnly() error {
	if scanRepoPath == "" && scanComponent == "" {
		return fmt.Errorf("--discover requires --repo-path or --component")
	}

	repoPath := scanRepoPath
	var repoCleanup func()
	if repoPath == "" && scanComponent != "" {
		var resolveErr error
		repoPath, repoCleanup, resolveErr = discover.ResolveComponentRepo(scanComponent)
		if resolveErr != nil {
			return fmt.Errorf("resolving repo for %s: %w", scanComponent, resolveErr)
		}
		if repoCleanup != nil {
			defer repoCleanup()
		}
	}

	ctx := context.Background()
	discResult, err := discover.Run(ctx, discover.Options{
		RepoPath:  repoPath,
		Component: scanComponent,
		JQL:       scanJQL,
		Since:     scanSince,
	})
	if err != nil {
		return fmt.Errorf("running discovery: %w", err)
	}

	gvcCVEs := make(map[string]bool)
	for _, v := range discResult.Vulns {
		for _, cve := range v.CVEIDs {
			gvcCVEs[cve] = true
		}
	}

	var trivyVulns []types.DiscoveredVuln
	if scanTrivy && repoPath != "" {
		fmt.Fprintf(os.Stderr, "\nRunning Trivy scan...\n")
		trivyReport, trivyErr := trivy.Run(repoPath)
		if trivyErr != nil {
			fmt.Fprintf(os.Stderr, "WARNING: Trivy scan failed: %v\n", trivyErr)
		} else {
			allTrivy := trivy.ToDiscoveredVulns(trivyReport, discResult.GoVersion)
			for i := range allTrivy {
				isGvc := false
				for _, cveID := range allTrivy[i].CVEIDs {
					if gvcCVEs[cveID] {
						isGvc = true
						break
					}
				}
				if isGvc {
					for j := range discResult.Vulns {
						for _, cveID := range discResult.Vulns[j].CVEIDs {
							for _, tCVE := range allTrivy[i].CVEIDs {
								if cveID == tCVE {
									if !strings.Contains(discResult.Vulns[j].Source, "T") {
									discResult.Vulns[j].Source = "G+T"
								}
								}
							}
						}
					}
				} else {
					allTrivy[i].Source = "Trivy"
					trivyVulns = append(trivyVulns, allTrivy[i])
				}
			}
			fmt.Fprintf(os.Stderr, "Trivy found %d vulnerabilities (%d unique after dedup)\n", len(allTrivy), len(trivyVulns))
		}
	}

	totalVulns := len(discResult.Vulns) + len(trivyVulns)
	if totalVulns == 0 {
		fmt.Println("No vulnerabilities discovered.")
		return nil
	}

	if len(trivyVulns) > 0 {
		discResult.Vulns = append(discResult.Vulns, trivyVulns...)
		discResult.TotalVulns = len(discResult.Vulns)
		discResult.NoTicket = discResult.TotalVulns - discResult.WithTicket
	}

	if scanShort {
		printDiscoverTable(discResult)
	} else {
		if err := printJSON(discResult); err != nil {
			return fmt.Errorf("marshaling output: %w", err)
		}
	}

	return nil
}

func runCombinedScan() error {
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
		if scanSince != "" {
			jql = injectSinceClause(jql, scanSince)
		}
	}

	tickets, err := jira.SearchTicketsCLI(jql)
	if err != nil {
		if err != jira.ErrCLINotFound {
			fmt.Fprintf(os.Stderr, "WARNING: jira CLI search failed (%v), falling back to REST API\n", err)
		}
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
	}

	fmt.Fprintf(os.Stderr, "Found %d CVE tickets. Assessing...\n", len(tickets))

	ctx := context.Background()
	var results []*types.Result
	var errors []string

	stderrColor := forceColor || term.IsTerminal(int(os.Stderr.Fd()))

	for i, ticket := range tickets {
		ticketID := ticket.Key
		if ticketID == "" {
			continue
		}

		ticketLink := termLink(ticketID, fmt.Sprintf("https://redhat.atlassian.net/browse/%s", ticketID))
		fmt.Fprintf(os.Stderr, "[%d/%d] %s ", i+1, len(tickets), ticketLink)

		if ticket.CVEID == "" {
			if stderrColor {
				fmt.Fprintf(os.Stderr, "%s[%s]%s no CVE ID (%sSKIP%s). Ticket is about: %s\n",
					colorForStatus(ticket.Status), ticket.Status, colorReset,
					colorNull, colorReset, ticket.Summary)
			} else {
				fmt.Fprintf(os.Stderr, "[%s] no CVE ID (SKIP). Ticket is about: %s\n", ticket.Status, ticket.Summary)
			}
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
		if stderrColor {
			sc := colorForStatus(ticket.Status)
			cc := colorForClassification(result.Recommendation.Classification)
			pc := colorForPriority(result.Recommendation.Priority)
			fmt.Fprintf(os.Stderr, "%s[%s]%s → %s%s%s (%s%s%s)\n",
				sc, ticket.Status, colorReset,
				cc, result.Recommendation.Classification, colorReset,
				pc, result.Recommendation.Priority, colorReset)
		} else {
			fmt.Fprintf(os.Stderr, "[%s] → %s (%s)\n", ticket.Status, result.Recommendation.Classification, result.Recommendation.Priority)
		}

		if scanJira {
			if err := report.PostToJira(result); err != nil {
				fmt.Fprintf(os.Stderr, "  WARNING: failed to post Jira comment: %v\n", err)
			}
		}

		if scanFix && result.Recommendation.Classification == types.FixableNow {
			fmt.Fprintf(os.Stderr, "  → Running fix pipeline for %s...\n", ticketID)
			fixResult, fixErr := fix.Run(ctx, fix.Options{
				TicketID: ticketID,
				RepoPath: scanRepoPath,
				Strategy: fix.StrategyAuto,
				DryRun:   fixDryRun,
				CreatePR: !fixDryRun,
				Jira:     scanJira,
			})
			if fixResult != nil {
				if jsonErr := printJSON(fixResult); jsonErr != nil {
					fmt.Fprintf(os.Stderr, "  WARNING: marshaling fix result: %v\n", jsonErr)
				}
			}
			if fixErr != nil {
				fmt.Fprintf(os.Stderr, "  WARNING: fix failed: %v\n", fixErr)
			}
		}
	}

	repoPath := scanRepoPath
	var repoCleanup func()
	if repoPath == "" && scanComponent != "" {
		var resolveErr error
		repoPath, repoCleanup, resolveErr = discover.ResolveComponentRepo(scanComponent)
		if resolveErr != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not resolve repo for %s: %v\n", scanComponent, resolveErr)
		}
		if repoCleanup != nil {
			defer repoCleanup()
		}
	}

	fmt.Fprintf(os.Stderr, "\nRunning govulncheck discovery...\n")
	discResult, err := discover.Run(ctx, discover.Options{
		RepoPath:  repoPath,
		Component: scanComponent,
		JQL:       jql,
		Since:     scanSince,
	})

	var discoveredGaps []types.DiscoveredVuln
	discCVEs := make(map[string]bool)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: govulncheck discovery failed: %v\n", err)
	} else {
		for _, dv := range discResult.Vulns {
			for _, cveID := range dv.CVEIDs {
				discCVEs[cveID] = true
			}
		}
		jiraCVEs := buildJiraCVESet(results)
		for i, dv := range discResult.Vulns {
			hasJiraMatch := false
			for _, cveID := range dv.CVEIDs {
				if jiraCVEs[cveID] {
					hasJiraMatch = true
					break
				}
			}
			if hasJiraMatch {
				discResult.Vulns[i].Source = "Multi"
			} else {
				discoveredGaps = append(discoveredGaps, dv)
			}
		}
		fmt.Fprintf(os.Stderr, "Found %d vulnerabilities (%d with ticket, %d new)\n", len(discResult.Vulns), len(discResult.Vulns)-len(discoveredGaps), len(discoveredGaps))
		for i, dv := range discoveredGaps {
			cve := formatCVEAliases(dv.CVEIDs, 0)
			if stderrColor {
				cc := colorForClassification(dv.Classification)
				pc := colorForPriority(dv.Priority)
				fmt.Fprintf(os.Stderr, "[%d/%d] %s package `%s` → %s%s%s (%s%s%s): %s\n",
					i+1, len(discoveredGaps), cve, dv.Package,
					cc, dv.Classification, colorReset,
					pc, dv.Priority, colorReset, dv.Description)
			} else {
				fmt.Fprintf(os.Stderr, "[%d/%d] %s package `%s` → %s (%s): %s\n",
					i+1, len(discoveredGaps), cve, dv.Package, dv.Classification, dv.Priority, dv.Description)
			}
		}
	}

	var trivyVulns []types.DiscoveredVuln
	if scanTrivy {
		fmt.Fprintf(os.Stderr, "\nRunning Trivy scan...\n")
		if repoPath != "" {
			trivyReport, trivyErr := trivy.Run(repoPath)
			if trivyErr != nil {
				fmt.Fprintf(os.Stderr, "WARNING: Trivy scan failed: %v\n", trivyErr)
			} else {
				goVer := ""
				if discResult != nil {
					goVer = discResult.GoVersion
				}
				allTrivy := trivy.ToDiscoveredVulns(trivyReport, goVer)
				jiraCVEs := buildJiraCVESet(results)
				for _, tv := range allTrivy {
					isJira := false
					isGvc := false
					for _, cveID := range tv.CVEIDs {
						if jiraCVEs[cveID] {
							isJira = true
						}
						if discCVEs[cveID] {
							isGvc = true
						}
					}
					if !isJira && !isGvc {
						trivyVulns = append(trivyVulns, tv)
					}
				}
				fmt.Fprintf(os.Stderr, "Trivy found %d vulnerabilities (%d unique after dedup)\n", len(allTrivy), len(trivyVulns))
			}
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: Trivy scan skipped (no repo path available)\n")
		}
	}

	if scanShort {
		printCombinedTable(results, discoveredGaps, discResult, trivyVulns, errors)
	} else {
		output := map[string]interface{}{
			"total":      len(tickets),
			"assessed":   len(results),
			"errors":     len(errors),
			"results":    results,
			"discovered": discoveredGaps,
			"trivy":      trivyVulns,
		}
		if err := printJSON(output); err != nil {
			return fmt.Errorf("marshaling output: %w", err)
		}
	}

	recordBlockedFromScan(results)

	if scanSummaryFile != "" {
		if err := writeBatchSummary(scanSummaryFile, results); err != nil {
			return fmt.Errorf("writing summary: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Summary written to %s\n", scanSummaryFile)
	}

	return nil
}

func buildJiraCVESet(results []*types.Result) map[string]bool {
	m := make(map[string]bool)
	for _, r := range results {
		cveID := extractCVEIDOnly(r.Vulnerability.CVEID)
		if cveID != "" {
			m[cveID] = true
		}
	}
	return m
}

func extractCVEIDOnly(s string) string {
	if i := strings.Index(s, " "); i > 0 {
		return s[:i]
	}
	return s
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

func printDiscoverTable(disc *types.DiscoverResult) {
	isTTY := forceColor || term.IsTerminal(int(os.Stdout.Fd()))

	headerFmt := "%-6s %-18s %-16s %-16s %-14s %-22s %5s %-14s\n"
	lineWidth := 140

	if isTTY {
		fmt.Printf("\033[1m"+headerFmt+colorReset,
			"SRC", "TICKET", "CVE", "CLASSIFICATION", "PRIORITY", "PACKAGE", "CVSS", "REACHABILITY")
		fmt.Println(strings.Repeat("─", lineWidth))
	} else {
		fmt.Printf(headerFmt,
			"SRC", "TICKET", "CVE", "CLASSIFICATION", "PRIORITY", "PACKAGE", "CVSS", "REACHABILITY")
		fmt.Println(strings.Repeat("-", lineWidth))
	}

	for _, v := range disc.Vulns {
		ticket := v.TicketID
		if ticket == "" {
			ticket = "-- none --"
		}
		src := v.Source
		if src == "" || src == "Scan" {
			src = "GVC"
		}
		cveCol := formatCVEAliases(v.CVEIDs, 16)
		class := string(v.Classification)
		priority := shortPriority(v.Priority)
		pkg := shortPackage(v.Package)

		if isTTY {
			classColor := colorForClassification(v.Classification)
			prioColor := colorForPriority(v.Priority)
			ticketColor := colorNull
			if v.HasTicket {
				ticketColor = colorLow
			}
			fmt.Printf("%-6s %s%-18s%s %-16s %s%-16s%s %s%-14s%s %-22s %5.1f %-14s\n",
				src,
				ticketColor, ticket, colorReset,
				cveCol,
				classColor, class, colorReset,
				prioColor, priority, colorReset,
				pkg, v.Severity, v.Reachability)
		} else {
			fmt.Printf("%-6s %-18s %-16s %-16s %-14s %-22s %5.1f %-14s\n",
				src, ticket, cveCol, class, priority, pkg, v.Severity, v.Reachability)
		}
	}

	if isTTY {
		fmt.Println(strings.Repeat("─", lineWidth))
	} else {
		fmt.Println(strings.Repeat("-", lineWidth))
	}

	fmt.Printf("%d discovered, %d with ticket, %d no ticket\n",
		disc.TotalVulns, disc.WithTicket, disc.NoTicket)
}

type combinedRow struct {
	src            string
	ticket         string
	ticketURL      string
	cveID          string
	cveURL         string
	version        string
	lang           string
	langSrc        string
	status         string
	rawStatus      string
	classification types.Classification
	priority       types.Priority
	pkg            string
	pkgSrc         string
	cvss           float64
	reachability   string
	callPaths      []string
	importChain    string
}

func buildCombinedRows(results []*types.Result, gaps []types.DiscoveredVuln, disc *types.DiscoverResult, trivyVulns []types.DiscoveredVuln) []combinedRow {
	discCVEs := make(map[string]bool)
	if disc != nil {
		for _, v := range disc.Vulns {
			for _, cveID := range v.CVEIDs {
				discCVEs[cveID] = true
			}
		}
	}
	trivyCVESet := make(map[string]bool)
	for _, v := range trivyVulns {
		for _, cveID := range v.CVEIDs {
			trivyCVESet[cveID] = true
		}
	}

	var rows []combinedRow
	for _, r := range results {
		cveID := shortCVEID(r.Vulnerability.CVEID)
		inGvc := discCVEs[cveID]
		inTrivy := trivyCVESet[cveID]
		src := compositeSource("J", inGvc, inTrivy)
		langSrc := "jira"
		pkgSrc := "jira"
		if inGvc {
			langSrc = "gvc"
			pkgSrc = "gvc"
		}
		var callPaths []string
		if ba := r.Analysis.ReleaseBranch; ba != nil {
			callPaths = ba.CallPaths
		} else if fu := r.Analysis.FixUpstream; fu != nil {
			callPaths = fu.CallPaths
		}
		rows = append(rows, combinedRow{
			src:            src,
			ticket:         extractTicketID(r.Source.TicketID),
			ticketURL:      extractTicketURL(r.Source.TicketID),
			cveID:          cveID,
			cveURL:         extractCVEURL(r.Vulnerability.CVEID),
			version:        extractVersion(r.Source.AffectedOperatorVersion),
			lang:           shortLanguage(r.Vulnerability.Language),
			langSrc:        langSrc,
			status:         shortStatus(r.Source.Status, r.Source.Resolution),
			rawStatus:      r.Source.Status,
			classification: r.Recommendation.Classification,
			priority:       r.Recommendation.Priority,
			pkg:            shortPackage(r.Vulnerability.Package),
			pkgSrc:         pkgSrc,
			cvss:           r.Vulnerability.Severity,
			reachability:   shortReachability(r),
			callPaths:      callPaths,
		})
	}
	for _, v := range gaps {
		gapInTrivy := false
		for _, cveID := range v.CVEIDs {
			if trivyCVESet[cveID] {
				gapInTrivy = true
				break
			}
		}
		rows = append(rows, combinedRow{
			src:            compositeSource("G", false, gapInTrivy),
			ticket:         "-- none --",
			cveID:          formatCVEAliases(v.CVEIDs, 16),
			version:        "",
			lang:           "Go",
			langSrc:        "gvc",
			status:         "",
			rawStatus:      "",
			classification: v.Classification,
			priority:       v.Priority,
			pkg:            shortPackage(v.Package),
			pkgSrc:         "gvc",
			cvss:           v.Severity,
			reachability:   v.Reachability,
			callPaths:      v.CallPaths,
			importChain:    v.ImportChain,
		})
	}
	for _, v := range trivyVulns {
		rows = append(rows, combinedRow{
			src:            "Trivy",
			ticket:         "-- none --",
			cveID:          formatCVEAliases(v.CVEIDs, 16),
			version:        "",
			lang:           "Go",
			langSrc:        "trivy",
			status:         "",
			rawStatus:      "",
			classification: v.Classification,
			priority:       v.Priority,
			pkg:            shortPackage(v.Package),
			pkgSrc:         "trivy",
			cvss:           v.Severity,
			reachability:   v.Reachability,
		})
	}

	sortCombinedRows(rows)
	return rows
}

func printCombinedTable(results []*types.Result, gaps []types.DiscoveredVuln, disc *types.DiscoverResult, trivyVulns []types.DiscoveredVuln, errors []string) {
	isTTY := forceColor || term.IsTerminal(int(os.Stdout.Fd()))
	rows := buildCombinedRows(results, gaps, disc, trivyVulns)

	headerFmt := "%-5s %-18s %-16s %-8s %-7s %-20s %-16s %-14s %-24s %5s %s\n"
	lineWidth := 176

	if isTTY {
		fmt.Printf("\033[1m"+headerFmt+colorReset,
			"SRC", "TICKET", "CVE", "VERSION", "LANG", "STATUS", "CLASSIFICATION", "PRIORITY", "PACKAGE", "CVSS", "REACHABILITY")
		fmt.Println(strings.Repeat("─", lineWidth))
	} else {
		fmt.Printf(headerFmt,
			"SRC", "TICKET", "CVE", "VERSION", "LANG", "STATUS", "CLASSIFICATION", "PRIORITY", "PACKAGE", "CVSS", "REACHABILITY")
		fmt.Println(strings.Repeat("-", lineWidth))
	}

	counts := map[types.Classification]int{}
	for _, row := range rows {
		class := string(row.classification)
		priority := shortPriority(row.priority)
		counts[row.classification]++

		langDisplay := row.lang
		if row.langSrc != "" {
			langDisplay = fmt.Sprintf("%s(%s)", row.lang, row.langSrc)
		}
		pkgDisplay := row.pkg
		if row.pkgSrc != "" && row.pkg != "" {
			pkgDisplay = fmt.Sprintf("%s(%s)", row.pkg, row.pkgSrc)
		}
		reachDisplay := row.reachability
		switch {
		case row.reachability == "MODULE-LEVEL":
			reachDisplay = "MODULE-LEVEL (go.mod only)"
		case row.reachability == "PACKAGE-LEVEL" && row.importChain != "":
			reachDisplay = fmt.Sprintf("PACKAGE-LEVEL (%s)", row.importChain)
		default:
			if ep := entryPointFile(row.callPaths); ep != "" {
				label := row.reachability
				if isTestPath(ep) && label == "REACHABLE" {
					label = "TEST-ONLY"
				}
				reachDisplay = fmt.Sprintf("%s (%s)", label, ep)
			}
		}

		if isTTY {
			ticketDisplay := termLink(fmt.Sprintf("%-18s", row.ticket), row.ticketURL)
			cveDisplay := termLink(fmt.Sprintf("%-16s", row.cveID), row.cveURL)
			classColor := colorForClassification(row.classification)
			prioColor := colorForPriority(row.priority)
			statusColor := colorForStatus(row.rawStatus)
			srcColor := colorForSource(row.src)
			fmt.Printf("%s%-5s%s %s %s %-8s %-7s %s%-20s%s %s%-16s%s %s%-14s%s %-24s %5.1f %s\n",
				srcColor, row.src, colorReset,
				ticketDisplay, cveDisplay, row.version, langDisplay,
				statusColor, row.status, colorReset,
				classColor, class, colorReset,
				prioColor, priority, colorReset,
				pkgDisplay, row.cvss, reachDisplay)
		} else {
			fmt.Printf("%-5s %-18s %-16s %-8s %-7s %-20s %-16s %-14s %-24s %5.1f %s\n",
				row.src, row.ticket, row.cveID, row.version, langDisplay, row.status, class, priority, pkgDisplay, row.cvss, reachDisplay)
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
	if len(gaps) > 0 {
		summary = append(summary, fmt.Sprintf("%d discovered (no ticket)", len(gaps)))
	}
	if len(trivyVulns) > 0 {
		summary = append(summary, fmt.Sprintf("%d trivy-only", len(trivyVulns)))
	}
	if len(errors) > 0 {
		summary = append(summary, fmt.Sprintf("%d errors", len(errors)))
	}
	fmt.Println(strings.Join(summary, ", "))
}

func statusRank(status string) int {
	base := strings.SplitN(status, " (", 2)[0]
	switch base {
	case "New", "To Do":
		return 0
	case "Backlog":
		return 1
	case "In Progress":
		return 2
	case "Code Review":
		return 3
	case "Review":
		return 4
	case "Release Pending":
		return 5
	case "Closed":
		if strings.Contains(status, "Won't Do") || strings.Contains(status, "Won't Fix") {
			return 6
		}
		if strings.Contains(status, "Not a Bug") {
			return 7
		}
		return 8
	case "":
		return 9
	default:
		return 8
	}
}

func sortCombinedRows(rows []combinedRow) {
	sourceRank := func(src string) int {
		if strings.Contains(src, "+") {
			return 0
		}
		switch src {
		case "Jira":
			return 1
		case "GVC":
			return 2
		case "Trivy":
			return 3
		default:
			return 4
		}
	}
	priorityOrder := map[types.Priority]int{
		types.PriorityCritical:    0,
		types.PriorityHigh:        1,
		types.PriorityMedium:      2,
		types.PriorityLow:         3,
		types.PriorityManual:      4,
		types.PriorityMisassigned: 5,
	}
	reachOrder := map[string]int{
		"REACHABLE": 0, "TEST-ONLY": 1, "PACKAGE-LEVEL": 2, "MODULE-LEVEL": 3, "UNKNOWN": 4, "N/A": 5,
	}

	sort.Slice(rows, func(i, j int) bool {
		si := sourceRank(rows[i].src)
		sj := sourceRank(rows[j].src)
		if si != sj {
			return si < sj
		}
		sti := statusRank(rows[i].status)
		stj := statusRank(rows[j].status)
		if sti != stj {
			return sti < stj
		}
		pi := priorityOrder[rows[i].priority]
		pj := priorityOrder[rows[j].priority]
		if pi != pj {
			return pi < pj
		}
		ri := reachOrder[rows[i].reachability]
		rj := reachOrder[rows[j].reachability]
		if ri != rj {
			return ri < rj
		}
		return rows[i].cvss > rows[j].cvss
	})
}

func formatCVEAliases(aliases []string, maxWidth int) string {
	if len(aliases) == 0 {
		return "N/A"
	}
	first := aliases[0]
	if maxWidth <= 0 {
		if len(aliases) == 1 {
			return first
		}
		return fmt.Sprintf("%s+%d", first, len(aliases)-1)
	}
	if len(aliases) == 1 {
		if len(first) > maxWidth && maxWidth > 3 {
			return first[:maxWidth-3] + "..."
		}
		return first
	}
	suffix := fmt.Sprintf("+%d", len(aliases)-1)
	avail := maxWidth - len(suffix)
	if len(first) > avail && avail > 3 {
		return first[:avail-3] + "..." + suffix
	}
	return first + suffix
}

func compositeSource(base string, inGvc, inTrivy bool) string {
	parts := []string{base}
	if inGvc && base != "G" {
		parts = append(parts, "G")
	}
	if inTrivy && base != "T" {
		parts = append(parts, "T")
	}
	if len(parts) == 1 {
		switch base {
		case "J":
			return "Jira"
		case "G":
			return "GVC"
		case "T":
			return "Trivy"
		}
	}
	return strings.Join(parts, "+")
}

func colorForSource(src string) string {
	if strings.Contains(src, "+") {
		return colorCyanBold
	}
	switch src {
	case "GVC":
		return colorMed
	case "Trivy":
		return colorHigh
	default:
		return colorString
	}
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
		return "Java"
	case "C":
		return "C"
	case "PHP":
		return "PHP"
	case "Perl":
		return "Perl"
	case "SQL":
		return "SQL"
	default:
		return "?"
	}
}

func extractVersion(s string) string {
	if i := strings.Index(s, ":"); i >= 0 {
		v := s[i+1:]
		if j := strings.Index(v, " ["); j >= 0 {
			v = v[:j]
		}
		return v
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

func entryPointFile(callPaths []string) string {
	if len(callPaths) == 0 {
		return ""
	}
	parts := strings.Split(callPaths[0], " → ")
	for i := len(parts) - 1; i >= 0; i-- {
		start := strings.LastIndex(parts[i], "(")
		end := strings.LastIndex(parts[i], ")")
		if start < 0 || end <= start {
			continue
		}
		filename := parts[i][start+1 : end]
		if strings.Contains(filename, "/") {
			base := filename[strings.LastIndex(filename, "/")+1:]
			if !strings.HasSuffix(base, ".go") {
				continue
			}
		}
		if strings.HasPrefix(filename, "net/") ||
			strings.HasPrefix(filename, "crypto/") ||
			strings.HasPrefix(filename, "internal/") ||
			strings.HasPrefix(filename, "encoding/") ||
			strings.HasPrefix(filename, "archive/") ||
			strings.HasPrefix(filename, "go/") ||
			strings.HasPrefix(filename, "golang.org/") ||
			strings.Contains(filename, "/vendor/") {
			continue
		}
		return filename
	}
	return ""
}

func isTestPath(path string) bool {
	return strings.HasSuffix(path, "_test.go") ||
		strings.HasPrefix(path, "test/") ||
		strings.Contains(path, "/test/") ||
		strings.Contains(path, "/tests/") ||
		strings.Contains(path, "/e2e/")
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

func injectSinceClause(jql, since string) string {
	var clause string
	if strings.ContainsAny(since, "-/") && len(since) > 3 {
		clause = fmt.Sprintf(` AND created >= "%s"`, since)
	} else {
		s := since
		if !strings.HasPrefix(s, "-") {
			s = "-" + s
		}
		clause = fmt.Sprintf(" AND created >= %s", s)
	}
	if idx := strings.Index(strings.ToUpper(jql), "ORDER BY"); idx != -1 {
		return jql[:idx] + clause + " " + jql[idx:]
	}
	return jql + clause
}

func init() {
	scanCmd.Flags().StringVar(&scanComponent, "component", "", "Component name (e.g., FAR, SNR, NHC, NMO, MDR)")
	scanCmd.Flags().StringVar(&scanJQL, "jql", "", "Custom JQL query")
	scanCmd.Flags().BoolVar(&scanJira, "jira", false, "Post assessments as Jira comments")
	scanCmd.Flags().StringVar(&scanSummaryFile, "summary-file", "", "Write aggregate summary to file")
	scanCmd.Flags().StringVar(&scanRepoPath, "repo-path", "", "Path to operator repo (auto-detected from Jira component if omitted)")
	scanCmd.Flags().BoolVar(&scanIncludeClosed, "include-closed", false, "Include closed tickets (historical reference)")
	scanCmd.Flags().BoolVar(&scanShort, "short", false, "Print compact summary table instead of full JSON")
	scanCmd.Flags().BoolVar(&scanDiscover, "discover", false, "Run govulncheck-only discovery (skip Jira assessment)")
	scanCmd.Flags().StringVar(&scanSince, "since", "", "Filter tickets by creation date (e.g., 1w, 30d, 1y, or 2025-01-01)")
	scanCmd.Flags().BoolVar(&scanTrivy, "trivy", true, "Run Trivy vulnerability scan (use --trivy=false to disable)")
	scanCmd.Flags().BoolVar(&scanFix, "fix", false, "Auto-fix Fixable Now tickets (use with --dry-run for preview)")
	rootCmd.AddCommand(scanCmd)
}
