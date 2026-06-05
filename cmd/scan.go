package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/razo7/vigil/pkg/assess"
	"github.com/razo7/vigil/pkg/cve"
	"github.com/razo7/vigil/pkg/discover"
	"github.com/razo7/vigil/pkg/fix"
	"github.com/razo7/vigil/pkg/goversion"
	"github.com/razo7/vigil/pkg/jira"
	"github.com/razo7/vigil/pkg/lifecycle"
	"github.com/razo7/vigil/pkg/route"
	"github.com/razo7/vigil/pkg/report"
	"github.com/razo7/vigil/pkg/sla"
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
	scanIncludeBugs   bool
	scanCommit        string
	scanGoVersion     string
	scanFormat        string
	scanDetectOnly    bool
	scanVerbose       bool
	scanBlame         bool
)

func loadComponentMap() map[string]string {
	return getConfig().ComponentMap()
}

func buildComponentJQL(component string) string {
	return fmt.Sprintf(
		`%s AND issuetype in (Vulnerability, Bug) AND component in ("%s") AND status not in (Closed) ORDER BY created DESC`,
		getConfig().Jira.ProjectJQL(), component,
	)
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
		repoPath, repoCleanup, resolveErr = discover.ResolveComponentRepo(scanComponent, loadComponentMap())
		if resolveErr != nil {
			return fmt.Errorf("resolving repo for %s: %w", scanComponent, resolveErr)
		}
		if repoCleanup != nil {
			defer repoCleanup()
		}
	}

	ctx := context.Background()
	discResult, err := discover.Run(ctx, discover.Options{
		RepoPath:     repoPath,
		Component:    scanComponent,
		JQL:          scanJQL,
		Since:        scanSince,
		ComponentMap: loadComponentMap(),
		ProjectJQL:   getConfig().Jira.ProjectJQL(),
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

func normalizeGoVersion(v string) string {
	if v == "" {
		return v
	}
	v = strings.TrimPrefix(v, "go")
	parts := strings.Split(v, ".")
	switch len(parts) {
	case 2:
		fmt.Fprintf(os.Stderr, "WARNING: --go-version %s treated as %s.0 (expected x.y.z format)\n", v, v)
		return v + ".0"
	case 1:
		fmt.Fprintf(os.Stderr, "WARNING: --go-version %s treated as %s.0.0 (expected x.y.z format)\n", v, v)
		return v + ".0.0"
	default:
		return v
	}
}

func runCombinedScan() error {
	if scanGoVersion == "" {
		scanGoVersion = os.Getenv("GO_VERSION")
	}
	if scanGoVersion != "" {
		scanGoVersion = normalizeGoVersion(scanGoVersion)
	}
	jql := scanJQL
	if jql == "" {
		key := strings.ToLower(scanComponent)
		fullName, ok := loadComponentMap()[key]
		if !ok {
			return fmt.Errorf("unknown component %q; use --jql for custom queries", scanComponent)
		}
		jql = buildComponentJQL(fullName)
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

	var cveTickets []jira.TicketInfo
	var skippedNonCVE int
	for _, t := range tickets {
		if t.Key == "" {
			continue
		}
		if t.CVEID == "" && !scanIncludeBugs {
			skippedNonCVE++
			continue
		}
		cveTickets = append(cveTickets, t)
	}

	if skippedNonCVE > 0 {
		fmt.Fprintf(os.Stderr, "Skipped %d non-CVE tickets (use --include-bugs to include)\n", skippedNonCVE)
	}

	if len(cveTickets) == 0 {
		fmt.Println("No CVE tickets found.")
	}

	fmt.Fprintf(os.Stderr, "Found %d CVE tickets. Assessing...\n", len(cveTickets))

	ctx := context.Background()
	var results []*types.Result
	var errors []string
	stderrColor := forceColor || term.IsTerminal(int(os.Stderr.Fd()))

	for i, ticket := range cveTickets {
		ticketID := ticket.Key

		ticketLink := termLink(ticketID, getConfig().Jira.BrowseURL(ticketID))
		if stderrColor {
			sc := colorForStatus(ticket.Status)
			fmt.Fprintf(os.Stderr, "[%d/%d] %s %s[%s]%s ", i+1, len(cveTickets), ticketLink, sc, ticket.Status, colorReset)
		} else {
			fmt.Fprintf(os.Stderr, "[%d/%d] %s [%s] ", i+1, len(cveTickets), ticketLink, ticket.Status)
		}

		result, err := assess.Run(ctx, assess.Options{
			TicketID:            ticketID,
			RepoPath:            scanRepoPath,
			Commit:              scanCommit,
			DownstreamGoVersion: scanGoVersion,
			Blame:               scanBlame,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			errors = append(errors, fmt.Sprintf("%s: %v", ticketID, err))
			continue
		}

		results = append(results, result)
		if stderrColor {
			cc := colorForClassification(result.Recommendation.Classification)
			pc := colorForPriority(result.Recommendation.Priority)
			fmt.Fprintf(os.Stderr, "→ %s%s%s (%s%s%s)\n",
				cc, result.Recommendation.Classification, colorReset,
				pc, result.Recommendation.Priority, colorReset)
		} else {
			fmt.Fprintf(os.Stderr, "→ %s (%s)\n", result.Recommendation.Classification, result.Recommendation.Priority)
		}

		if scanJira {
			if err := report.PostToJira(result); err != nil {
				fmt.Fprintf(os.Stderr, "  WARNING: failed to post Jira comment: %v\n", err)
			}
		}

		if scanFix && !scanDetectOnly && result.Recommendation.Classification == types.FixableNow {
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
		repoPath, repoCleanup, resolveErr = discover.ResolveComponentRepo(scanComponent, loadComponentMap())
		if resolveErr != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not resolve repo for %s: %v\n", scanComponent, resolveErr)
		}
		if repoCleanup != nil {
			defer repoCleanup()
		}
	}

	fmt.Fprintf(os.Stderr, "\nRunning govulncheck discovery (main)...\n")
	discResult, err := discover.Run(ctx, discover.Options{
		RepoPath:     repoPath,
		Component:    scanComponent,
		JQL:          jql,
		Since:        scanSince,
		ComponentMap: loadComponentMap(),
		ProjectJQL:   getConfig().Jira.ProjectJQL(),
		Blame:        scanBlame,
	})

	operatorName := assess.DeriveOperatorName(loadComponentMap()[strings.ToLower(scanComponent)])
	supportedVersions := lifecycle.SupportedOperatorVersions(operatorName)
	if repoPath != "" && len(supportedVersions) > 0 {
		cveBranches := make(map[string][]string)
		if discResult != nil {
			for _, v := range discResult.Vulns {
				for _, cve := range v.CVEIDs {
					cveBranches[cve] = append(cveBranches[cve], "main")
				}
			}
		}
		for _, ver := range supportedVersions {
			branchVer := lifecycle.LookupUpstreamVersion(operatorName, ver)
			branch := goversion.ReleaseBranch(branchVer)
			if !goversion.HasBranch(repoPath, branch) {
				fmt.Fprintf(os.Stderr, "  Skipping %s (branch not found in repo)\n", branch)
				continue
			}
			wt, cleanup, wtErr := goversion.CreateWorktree(repoPath, branch)
			if wtErr != nil {
				continue
			}
			fmt.Fprintf(os.Stderr, "Running govulncheck on %s...\n", branch)
			goMod, modErr := goversion.ReadGoMod(wt)
			if modErr != nil {
				cleanup()
				continue
			}
			var branchResult *goversion.VulncheckResult
			var branchErr error
			if scanBlame {
				branchResult, branchErr = goversion.RunGovulncheckWithBlame(wt, goMod.EffectiveVersion())
			} else {
				branchResult, branchErr = goversion.RunGovulncheckWithVersion(wt, goMod.EffectiveVersion())
			}

			if scanTrivy {
				trivyReport, trivyErr := trivy.Run(wt)
				if trivyErr == nil {
					branchTrivy := trivy.ToDiscoveredVulns(trivyReport, goMod.EffectiveVersion())
					for _, tv := range branchTrivy {
						for _, cveID := range tv.CVEIDs {
							if existing := cveBranches[cveID]; len(existing) > 0 {
								cveBranches[cveID] = append(cveBranches[cveID], branch)
							} else {
								cveBranches[cveID] = []string{branch}
								tv.Source = fmt.Sprintf("Trivy(%s)", branch)
								tv.Version = ver
								if discResult == nil {
									discResult = &types.DiscoverResult{}
								}
								discResult.Vulns = append(discResult.Vulns, tv)
								discResult.TotalVulns++
								discResult.NoTicket++
							}
						}
					}
				}
			}
			cleanup()
			if branchErr != nil {
				fmt.Fprintf(os.Stderr, "WARNING: govulncheck on %s failed: %v\n", branch, branchErr)
				continue
			}
			newCount := 0
			for _, entry := range branchResult.Vulns {
				for _, alias := range entry.Aliases {
					if existing := cveBranches[alias]; len(existing) > 0 {
						cveBranches[alias] = append(cveBranches[alias], branch)
						if discResult != nil {
							for i := range discResult.Vulns {
								for _, cve := range discResult.Vulns[i].CVEIDs {
									if cve == alias {
										discResult.Vulns[i].Source += "+" + branch
									}
								}
							}
						}
						continue
					}
					cveBranches[alias] = []string{branch}
					newCount++
					if discResult == nil {
						discResult = &types.DiscoverResult{}
					}
					dv := types.DiscoveredVuln{
						CVEIDs:           []string{alias},
						Package:          entry.Package,
						Description:      entry.ID,
						Source:            fmt.Sprintf("GVC(%s)", branch),
						Version:          ver,
						CurrentGo:        goMod.EffectiveVersion(),
						FixVersion:       entry.FixVersion,
						InstalledVersion: entry.InstalledVersion,
						CallPaths:        entry.CallPaths,
					}
					if entry.Reachable {
						dv.Reachability = "REACHABLE"
						dv.Classification = types.FixableNow
						dv.Priority = types.PriorityHigh
					} else if !entry.ModuleOnly {
						dv.Reachability = "PACKAGE-LEVEL"
						dv.Classification = types.FixableNow
						dv.Priority = types.PriorityMedium
					} else {
						dv.Reachability = "MODULE-LEVEL"
						dv.Classification = types.NotReachable
						dv.Priority = types.PriorityLow
					}
					discResult.Vulns = append(discResult.Vulns, dv)
					discResult.TotalVulns++
					discResult.NoTicket++
				}
			}
			if newCount > 0 {
				fmt.Fprintf(os.Stderr, "  %s: %d new CVEs (also affects previously found CVEs)\n", branch, newCount)
			}
		}
	}

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
		if len(discResult.Vulns) == 0 {
			fmt.Fprintf(os.Stderr, "govulncheck: no reachable vulnerabilities found\n")
		} else {
			fmt.Fprintf(os.Stderr, "govulncheck: found %d vulnerabilities (%d with ticket, %d new)\n", len(discResult.Vulns), len(discResult.Vulns)-len(discoveredGaps), len(discoveredGaps))
		}
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

	cvssCount := 0
	cvssTotal := 0
	for _, d := range discoveredGaps {
		if d.Severity == 0 {
			cvssTotal++
		}
	}
	for _, d := range trivyVulns {
		if d.Severity == 0 {
			cvssTotal++
		}
	}
	if cvssTotal > 0 {
		fmt.Fprintf(os.Stderr, "Fetching CVSS for %d discovered CVEs...\n", cvssTotal)
	}
	for i := range discoveredGaps {
		if discoveredGaps[i].Severity == 0 && len(discoveredGaps[i].CVEIDs) > 0 {
			enrichDiscoveredVuln(&discoveredGaps[i])
			cvssCount++
		}
	}
	for i := range trivyVulns {
		if trivyVulns[i].Severity == 0 && len(trivyVulns[i].CVEIDs) > 0 {
			enrichDiscoveredVuln(&trivyVulns[i])
			cvssCount++
		}
	}
	if cvssCount > 0 {
		fmt.Fprintf(os.Stderr, "Fetched CVSS for %d CVEs\n", cvssCount)
	}

	if scanDetectOnly {
		output := types.DetectionOutput{
			Findings:   results,
			Discovered: append(discoveredGaps, trivyVulns...),
			Metadata: types.DetectionMetadata{
				Component: scanComponent,
				RepoPath:  repoPath,
				ScannedAt: time.Now(),
			},
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(output)
	}

	if scanFormat == "html" {
		if term.IsTerminal(int(os.Stdout.Fd())) {
			filename := fmt.Sprintf("vigil-%s-%s.html", strings.ToLower(scanComponent), time.Now().Format("2006-01-02"))
			f, err := os.Create(filename)
			if err != nil {
				return fmt.Errorf("creating report file: %w", err)
			}
			origStdout := os.Stdout
			os.Stdout = f
			printHTMLTable(results, discoveredGaps, discResult, trivyVulns, scanVerbose)
			os.Stdout = origStdout
			f.Close()
			fmt.Fprintf(os.Stderr, "Report written to %s\n", filename)
		} else {
			printHTMLTable(results, discoveredGaps, discResult, trivyVulns, scanVerbose)
		}
	} else if scanShort {
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

func preferCVEIDs(ids []string) []string {
	var cves, others []string
	for _, id := range ids {
		if strings.HasPrefix(id, "CVE-") {
			cves = append(cves, id)
		} else {
			others = append(others, id)
		}
	}
	return append(cves, others...)
}

func cveOrgURL(cveIDs []string) string {
	for _, id := range cveIDs {
		if strings.HasPrefix(id, "CVE-") {
			return fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", id)
		}
	}
	for _, id := range cveIDs {
		if strings.HasPrefix(id, "GHSA-") {
			return fmt.Sprintf("https://github.com/advisories/%s", id)
		}
	}
	return ""
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
		case types.Unknown:
			summary.Unknown++
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

func colWidth(header string, vals []string) int {
	w := len(header)
	for _, v := range vals {
		if len(v) > w {
			w = len(v)
		}
	}
	return w
}

func printDiscoverTable(disc *types.DiscoverResult) {
	isTTY := forceColor || term.IsTerminal(int(os.Stdout.Fd()))

	type discRow struct {
		cve, severity, reach, pkg, version, class, ticket, src string
		priorityVal                                            types.Priority
		classification                                         types.Classification
	}
	var rows []discRow
	for _, v := range disc.Vulns {
		ticket := v.TicketID
		if ticket == "" {
			ticket = "—"
		}
		src := v.Source
		if src == "" || src == "Scan" {
			src = "GVC"
		}
		ver := strings.TrimPrefix(v.Version, "v")
		if ver == "" {
			ver = "main"
		}
		rows = append(rows, discRow{
			cve:            formatCVEAliases(preferCVEIDs(v.CVEIDs), 0),
			severity:       fmt.Sprintf("%s (%.1f)", shortPriority(v.Priority), v.Severity),
			reach:          v.Reachability,
			pkg:            shortPackage(v.Package),
			version:        ver,
			class:          string(v.Classification),
			ticket:         ticket,
			src:            src,
			priorityVal:    v.Priority,
			classification: v.Classification,
		})
	}

	cols := make([][]string, 8)
	for _, r := range rows {
		cols[0] = append(cols[0], r.cve)
		cols[1] = append(cols[1], r.severity)
		cols[2] = append(cols[2], r.reach)
		cols[3] = append(cols[3], r.pkg)
		cols[4] = append(cols[4], r.version)
		cols[5] = append(cols[5], r.class)
		cols[6] = append(cols[6], r.ticket)
		cols[7] = append(cols[7], r.src)
	}
	headers := []string{"CVE", "SEVERITY", "REACHABILITY", "PACKAGE", "VERSION", "ACTION", "TICKET", "SRC"}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = colWidth(h, cols[i])
	}

	fmtStr := fmt.Sprintf("%%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds\n",
		widths[0], widths[1], widths[2], widths[3], widths[4], widths[5], widths[6], widths[7])
	lineWidth := 0
	for _, w := range widths {
		lineWidth += w
	}
	lineWidth += len(widths) - 1

	if isTTY {
		fmt.Printf("\033[1m"+fmtStr+colorReset, "CVE", "SEVERITY", "REACHABILITY", "PACKAGE", "VERSION", "ACTION", "TICKET", "SRC")
		fmt.Println(strings.Repeat("─", lineWidth))
	} else {
		fmt.Printf(fmtStr, "CVE", "SEVERITY", "REACHABILITY", "PACKAGE", "VERSION", "ACTION", "TICKET", "SRC")
		fmt.Println(strings.Repeat("-", lineWidth))
	}

	for _, r := range rows {
		if isTTY {
			prioColor := colorForPriority(r.priorityVal)
			classColor := colorForClassification(r.classification)
			fmt.Printf(fmt.Sprintf("%%-%ds %%s%%-%ds%%s %%-%ds %%-%ds %%-%ds %%s%%-%ds%%s %%-%ds %%-%ds\n",
				widths[0], widths[1], widths[2], widths[3], widths[4], widths[5], widths[6], widths[7]),
				r.cve,
				prioColor, r.severity, colorReset,
				r.reach, r.pkg, r.version,
				classColor, r.class, colorReset,
				r.ticket, r.src)
		} else {
			fmt.Printf(fmtStr,
				r.cve, r.severity, r.reach, r.pkg, r.version, r.class, r.ticket, r.src)
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
	src                 string
	ticket              string
	ticketURL           string
	cveID               string
	cveURL              string
	version             string
	lang                string
	status              string
	rawStatus           string
	classification      types.Classification
	priority            types.Priority
	pkg                 string
	cvss                float64
	reachability        string
	callPaths           []string
	importChain         string
	created             string
	slaDueDate          string
	slaStatus           string
	fixVersion          string
	installedVersion    string
	currentGo           string
	fixRoute            route.Route
	fixFunctionMismatch bool
	misassignReason     string
}

type groupedRow struct {
	combinedRow
	subRows []combinedRow
}

func reachabilityRank(r string) int {
	switch r {
	case "REACHABLE":
		return 0
	case "TEST-ONLY":
		return 1
	case "PACKAGE-LEVEL":
		return 2
	case "MODULE-LEVEL":
		return 3
	case "UNKNOWN":
		return 4
	default:
		return 5
	}
}

func groupByCVE(rows []combinedRow) []groupedRow {
	type group struct {
		rows []combinedRow
	}
	orderKeys := make([]string, 0)
	groups := make(map[string]*group)
	for _, r := range rows {
		key := r.cveID
		if g, ok := groups[key]; ok {
			g.rows = append(g.rows, r)
		} else {
			orderKeys = append(orderKeys, key)
			groups[key] = &group{rows: []combinedRow{r}}
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

	var result []groupedRow
	for _, key := range orderKeys {
		g := groups[key]
		if len(g.rows) == 1 {
			result = append(result, groupedRow{combinedRow: g.rows[0]})
			continue
		}

		summary := g.rows[0]

		versionSet := map[string]bool{}
		ticketSet := map[string]bool{}
		statusSet := map[string]bool{}
		var versions []string
		var tickets []string
		var statuses []string

		for _, r := range g.rows {
			if !versionSet[r.version] {
				versionSet[r.version] = true
				versions = append(versions, r.version)
			}
			if r.ticket != "-- none --" && r.ticket != "" && !ticketSet[r.ticket] {
				ticketSet[r.ticket] = true
				tickets = append(tickets, r.ticket)
			}
			if r.rawStatus != "" && r.rawStatus != "No ticket" && !statusSet[r.rawStatus] {
				statusSet[r.rawStatus] = true
				statuses = append(statuses, r.rawStatus)
			}

			if priorityOrder[r.priority] < priorityOrder[summary.priority] {
				summary.priority = r.priority
			}
			if reachabilityRank(r.reachability) < reachabilityRank(summary.reachability) {
				summary.reachability = r.reachability
				summary.callPaths = r.callPaths
				summary.importChain = r.importChain
			}
			if r.cvss > summary.cvss {
				summary.cvss = r.cvss
			}
			if r.created != "" && (summary.created == "" || r.created < summary.created) {
				summary.created = r.created
			}
			if r.slaDueDate != "" && (summary.slaDueDate == "" || r.slaDueDate < summary.slaDueDate) {
				summary.slaDueDate = r.slaDueDate
				summary.slaStatus = r.slaStatus
			}
			if actionRank(r) < actionRank(summary) {
				summary.classification = r.classification
				summary.fixRoute = r.fixRoute
				summary.fixFunctionMismatch = r.fixFunctionMismatch
				summary.misassignReason = r.misassignReason
			}
			if r.ticketURL != "" && summary.ticketURL == "" {
				summary.ticketURL = r.ticketURL
			}
		}

		summary.version = strings.Join(versions, ",")
		if len(tickets) > 0 {
			if len(statuses) == 1 {
				summary.ticket = strings.Join(tickets, ",")
				summary.status = statuses[0]
				summary.rawStatus = statuses[0]
			} else if len(statuses) > 1 {
				var ticketsWithStatus []string
				seen := map[string]bool{}
				for _, r := range g.rows {
					if r.ticket == "-- none --" || r.ticket == "" || seen[r.ticket] {
						continue
					}
					seen[r.ticket] = true
					ticketsWithStatus = append(ticketsWithStatus, fmt.Sprintf("%s(%s)", r.ticket, r.rawStatus))
				}
				summary.ticket = strings.Join(ticketsWithStatus, ", ")
				summary.status = ""
				summary.rawStatus = statuses[0]
			} else {
				summary.ticket = strings.Join(tickets, ",")
			}
		}

		result = append(result, groupedRow{combinedRow: summary, subRows: g.rows})
	}
	return result
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
		var callPaths []string
		if ba := r.Analysis.ReleaseBranch; ba != nil {
			callPaths = ba.CallPaths
		} else if fu := r.Analysis.FixUpstream; fu != nil {
			callPaths = fu.CallPaths
		}
		ver := extractVersion(r.Source.AffectedOperatorVersion)
		if ver == "" {
			ver = "main"
		}
		rows = append(rows, combinedRow{
			src:                 src,
			ticket:              extractTicketID(r.Source.TicketID),
			ticketURL:           extractTicketURL(r.Source.TicketID),
			cveID:               cveID,
			cveURL:              extractCVEURL(r.Vulnerability.CVEID),
			version:             ver,
			lang:                shortLanguage(r.Vulnerability.Language),
			status:              shortStatus(r.Source.Status, r.Source.Resolution),
			rawStatus:           r.Source.Status,
			classification:      r.Recommendation.Classification,
			priority:            r.Recommendation.Priority,
			pkg:                 shortPackage(r.Vulnerability.Package),
			cvss:                r.Vulnerability.Severity,
			reachability:        shortReachability(r),
			callPaths:           callPaths,
			importChain:         buildImportChainForResult(r, callPaths),
			created:             r.Source.Created,
			slaDueDate:          r.Source.SLADueDate,
			slaStatus:           r.Source.SLAStatus,
			fixVersion:          shortFixVersion(r.Vulnerability.FixVersion),
			currentGo:           extractCurrentGo(r),
			fixRoute:            route.Decide(r),
			fixFunctionMismatch: strings.Contains(r.Recommendation.MisassignReason, "fix functions not called"),
			misassignReason:     r.Recommendation.MisassignReason,
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
		gapVersion := strings.TrimPrefix(v.Version, "v")
		if gapVersion == "" {
			gapVersion = "main"
		}
		sortedIDs := preferCVEIDs(v.CVEIDs)
		gapCurrentGo := v.CurrentGo
		if gapCurrentGo == "" && disc != nil {
			gapCurrentGo = disc.GoVersion
		}
		gapRow := combinedRow{
			src:            compositeSource("G", false, gapInTrivy),
			ticket:         "-- none --",
			cveID:          formatCVEAliases(sortedIDs, 0),
			cveURL:         cveOrgURL(sortedIDs),
			version:        gapVersion,
			lang:           "Go",
			status:         "No ticket",
			rawStatus:      "No ticket",
			classification: v.Classification,
			priority:       v.Priority,
			pkg:            shortPackage(v.Package),
			cvss:           v.Severity,
			reachability:   v.Reachability,
			callPaths:      v.CallPaths,
			importChain:    v.ImportChain,
			created:        v.CVEPublished,
			fixVersion:       shortFixVersion(v.FixVersion),
			installedVersion: v.InstalledVersion,
			currentGo:        gapCurrentGo,
		}
		calculateDiscoveredSLA(&gapRow, v.CVEPublished, v.Severity, v.SeverityLabel, v.Priority)
		rows = append(rows, gapRow)
	}
	for _, v := range trivyVulns {
		trivySortedIDs := preferCVEIDs(v.CVEIDs)
		trivyCurrentGo := ""
		if disc != nil {
			trivyCurrentGo = disc.GoVersion
		}
		trivyRow := combinedRow{
			src:            "Trivy",
			ticket:         "-- none --",
			cveID:          formatCVEAliases(trivySortedIDs, 0),
			cveURL:         cveOrgURL(trivySortedIDs),
			version:        "main",
			lang:           "Go",
			status:         "No ticket",
			rawStatus:      "No ticket",
			classification: v.Classification,
			priority:       v.Priority,
			pkg:            shortPackage(v.Package),
			cvss:           v.Severity,
			reachability:   v.Reachability,
			created:        v.CVEPublished,
			fixVersion:     shortFixVersion(v.FixVersion),
			currentGo:      trivyCurrentGo,
		}
		calculateDiscoveredSLA(&trivyRow, v.CVEPublished, v.Severity, v.SeverityLabel, v.Priority)
		rows = append(rows, trivyRow)
	}

	sortCombinedRows(rows)
	return rows
}

func printCombinedTable(results []*types.Result, gaps []types.DiscoveredVuln, disc *types.DiscoverResult, trivyVulns []types.DiscoveredVuln, errors []string) {
	isTTY := forceColor || term.IsTerminal(int(os.Stdout.Fd()))
	rows := buildCombinedRows(results, gaps, disc, trivyVulns)
	grouped := groupByCVE(rows)

	type renderedRow struct {
		cveID, cveURL, severity, reach, pkg, version string
		action, ticket, ticketURL, slaDue, created   string
		src, rawStatus, slaStatus                    string
		classification                               types.Classification
		priorityVal                                  types.Priority
	}

	cveVersions := map[string][]string{}
	latestVer := ""
	for _, r := range rows {
		if r.version != "" {
			cveVersions[r.cveID] = append(cveVersions[r.cveID], r.version)
			if latestVer == "" || compareVersionStrings(r.version, latestVer) > 0 {
				latestVer = r.version
			}
		}
	}
	for _, r := range rows {
		if r.ticket == "-- none --" {
			cveVersions[r.cveID] = append(cveVersions[r.cveID], "main")
		}
	}

	var rendered []renderedRow
	counts := map[types.Classification]int{}

	for _, gr := range grouped {
		row := gr.combinedRow
		counts[row.classification]++

		severity := fmt.Sprintf("%s (%.1f)", shortPriority(row.priority), row.cvss)

		srcDisplay := row.src
		if row.lang != "Go" {
			srcDisplay = fmt.Sprintf("%s (%s)", row.src, row.lang)
		}

		pkgDisplay := row.pkg

		reachDisplay := row.reachability
		switch {
		case row.reachability == "MODULE-LEVEL":
			reachDisplay = "MODULE-LEVEL (go.mod only)"
		case row.reachability == "PACKAGE-LEVEL" && row.importChain != "":
			chain := row.importChain
			if len(chain) > 60 {
				parts := strings.Split(chain, " → ")
				if len(parts) > 3 {
					chain = parts[0] + " → ... → " + parts[len(parts)-1]
				}
			}
			reachDisplay = fmt.Sprintf("PACKAGE-LEVEL (%s)", chain)
		default:
			if ep := entryPointFile(row.callPaths); ep != "" {
				label := row.reachability
				if isTestPath(ep) && label == "REACHABLE" {
					label = "TEST-ONLY"
				}
				reachDisplay = fmt.Sprintf("%s (%s)", label, ep)
			}
		}

		ticketWithStatus := row.ticket
		if row.ticket == "-- none --" {
			ticketWithStatus = "—"
		} else if row.status != "" && row.status != "No ticket" {
			ticketWithStatus = fmt.Sprintf("%s (%s)", row.ticket, row.status)
		}

		slaDue := row.slaDueDate
		if slaDue == "" {
			slaDue = "—"
		}

		actionText := buildAction(row, latestVer, cveVersions)
		if len(gr.subRows) > 1 && row.classification == types.FixableNow {
			if perVersion := buildPerVersionAction(gr.subRows, latestVer, cveVersions); perVersion != "" {
				actionText = perVersion
			}
		}

		rendered = append(rendered, renderedRow{
			cveID:          row.cveID,
			cveURL:         row.cveURL,
			severity:       severity,
			reach:          reachDisplay,
			pkg:            pkgDisplay,
			version:        row.version,
			action:         actionText,
			ticket:         ticketWithStatus,
			ticketURL:      row.ticketURL,
			slaDue:         slaDue,
			created:        row.created,
			src:            srcDisplay,
			rawStatus:      row.rawStatus,
			slaStatus:      row.slaStatus,
			classification: row.classification,
			priorityVal:    row.priority,
		})
	}

	headers := []string{"CVE", "SEVERITY", "REACHABILITY", "PACKAGE", "VERSION", "ACTION", "TICKET", "DUE", "CREATED", "SRC"}
	cols := make([][]string, len(headers))
	for _, r := range rendered {
		cols[0] = append(cols[0], r.cveID)
		cols[1] = append(cols[1], r.severity)
		cols[2] = append(cols[2], r.reach)
		cols[3] = append(cols[3], r.pkg)
		cols[4] = append(cols[4], r.version)
		cols[5] = append(cols[5], r.action)
		cols[6] = append(cols[6], r.ticket)
		cols[7] = append(cols[7], r.slaDue)
		cols[8] = append(cols[8], r.created)
		cols[9] = append(cols[9], r.src)
	}
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = colWidth(h, cols[i])
	}
	const maxActionWidth = 45
	if w[5] > maxActionWidth {
		w[5] = maxActionWidth
	}

	fmtStr := fmt.Sprintf("%%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds\n",
		w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8], w[9])
	lineWidth := 0
	for _, ww := range w {
		lineWidth += ww
	}
	lineWidth += len(w) - 1

	if isTTY {
		fmt.Printf("\033[1m"+fmtStr+colorReset,
			"CVE", "SEVERITY", "REACHABILITY", "PACKAGE", "VERSION", "ACTION", "TICKET", "DUE", "CREATED", "SRC")
		fmt.Println(strings.Repeat("─", lineWidth))
	} else {
		fmt.Printf(fmtStr,
			"CVE", "SEVERITY", "REACHABILITY", "PACKAGE", "VERSION", "ACTION", "TICKET", "DUE", "CREATED", "SRC")
		fmt.Println(strings.Repeat("-", lineWidth))
	}

	for _, r := range rendered {
		actionDisplay := r.action
		if len(actionDisplay) > maxActionWidth {
			actionDisplay = actionDisplay[:maxActionWidth-3] + "..."
		}
		if isTTY {
			cveDisplay := termLink(fmt.Sprintf("%-*s", w[0], r.cveID), r.cveURL)
			ticketDisplay := termLink(fmt.Sprintf("%-*s", w[6], r.ticket), r.ticketURL)
			prioColor := colorForPriority(r.priorityVal)
			actionColor := colorForAction(r.action)
			dueColor := colorForDate(r.slaDue)
			fmt.Printf(fmt.Sprintf("%%s %%s%%-%ds%%s %%-%ds %%-%ds %%-%ds %%s%%-%ds%%s %%s %%s%%-%ds%%s %%-%ds %%-%ds\n",
				w[1], w[2], w[3], w[4], w[5], w[7], w[8], w[9]),
				cveDisplay,
				prioColor, r.severity, colorReset,
				r.reach, r.pkg, r.version,
				actionColor, actionDisplay, colorReset,
				ticketDisplay,
				dueColor, r.slaDue, colorReset,
				r.created, r.src)
		} else {
			fmt.Printf(fmt.Sprintf("%%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds\n",
				w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8], w[9]),
				r.cveID, r.severity, r.reach, r.pkg, r.version, actionDisplay, r.ticket, r.slaDue, r.created, r.src)
		}
	}

	if isTTY {
		fmt.Println(strings.Repeat("─", lineWidth))
	} else {
		fmt.Println(strings.Repeat("-", lineWidth))
	}

	total := len(grouped)
	actionSummary := map[string]int{}
	for _, r := range rendered {
		switch {
		case strings.Contains(r.action, "Fix"):
			actionSummary["fix"]++
		case strings.Contains(r.action, "Blocked"):
			actionSummary["blocked"]++
		case strings.Contains(r.action, "Skip"):
			actionSummary["skip"]++
		case strings.Contains(r.action, "No action"), strings.Contains(r.action, "Affected"):
			actionSummary["safe"]++
		case strings.Contains(r.action, "Manual"):
			actionSummary["manual"]++
		default:
			actionSummary["other"]++
		}
	}
	var parts []string
	if n := actionSummary["fix"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d fixable", n))
	}
	if n := actionSummary["blocked"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d blocked", n))
	}
	if n := actionSummary["skip"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d skip", n))
	}
	if n := actionSummary["safe"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d safe", n))
	}
	if n := actionSummary["manual"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d manual", n))
	}
	if len(errors) > 0 {
		parts = append(parts, fmt.Sprintf("%d errors", len(errors)))
	}
	sources := fmt.Sprintf("(%d Jira, %d discovered)", len(results), len(gaps)+len(trivyVulns))
	fmt.Printf("%d CVEs: %s %s\n", total, strings.Join(parts, ", "), sources)

	threshold := getConfig().EOLThresholdDuration()
	if threshold > 0 {
		fmt.Fprintf(os.Stderr, "ℹ️  Versions with <%s remaining support are deprioritized (--eol-threshold)\n", getConfig().EOLThreshold)
	} else if isTTY {
		fmt.Fprintf(os.Stderr, "💡 Tip: use --eol-threshold 90d to deprioritize versions nearing end of support\n")
	}
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

func enrichDiscoveredVuln(v *types.DiscoveredVuln) {
	id := ""
	for _, candidate := range v.CVEIDs {
		if strings.HasPrefix(candidate, "CVE-") {
			id = candidate
			break
		}
	}
	if id == "" && len(v.CVEIDs) > 0 {
		id = v.CVEIDs[0]
	}
	if id == "" {
		return
	}
	info, err := cve.FetchWithFallback(id)
	if err != nil || info == nil {
		return
	}
	if info.Score > 0 {
		v.Severity = info.Score
	}
	if info.Severity != "" {
		v.SeverityLabel = info.Severity
	}
	if v.CVEPublished == "" && info.Published != "" {
		v.CVEPublished = info.Published
	}
	if info.CVEID != "" {
		hasCVE := false
		for _, existing := range v.CVEIDs {
			if existing == info.CVEID {
				hasCVE = true
				break
			}
		}
		if !hasCVE {
			v.CVEIDs = append([]string{info.CVEID}, v.CVEIDs...)
		}
	}
}

func severityLabelFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func calculateDiscoveredSLA(row *combinedRow, published string, severity float64, severityLabel string, priority types.Priority) {
	if published == "" {
		return
	}
	if severityLabel == "" && severity > 0 {
		severityLabel = severityLabelFromScore(severity)
	}
	if severityLabel == "" && priority != "" {
		severityLabel = string(priority)
	}
	if severityLabel == "" {
		return
	}
	pub, err := time.Parse("2006-01-02", published)
	if err != nil {
		return
	}
	label := severityLabel
	if label == "" {
		label = severityLabelFromScore(severity)
	}
	slaDue := sla.CalculateSLADate(pub, label)
	if slaDue.IsZero() {
		return
	}
	row.slaDueDate = slaDue.Format("2006-01-02")
	st, _ := sla.Status(slaDue)
	row.slaStatus = st
}

func buildImportChainForResult(r *types.Result, callPaths []string) string {
	if len(callPaths) > 0 {
		return ""
	}
	reach := ""
	if ba := r.Analysis.ReleaseBranch; ba != nil {
		reach = ba.Reachability
	}
	if reach != "PACKAGE-LEVEL" && reach != "PACKAGE_LEVEL" {
		return ""
	}
	pkg := r.Vulnerability.Package
	if pkg == "" {
		return ""
	}
	operatorName := ""
	if av := r.Source.AffectedOperatorVersion; av != "" {
		parts := strings.SplitN(av, " ", 2)
		if len(parts) > 0 {
			operatorName = parts[0]
		}
	}
	if operatorName == "" {
		operatorName = "operator"
	}
	return operatorName + " → " + pkg
}

func buildAction(row combinedRow, latestVer string, cveVersions map[string][]string) string {
	switch row.classification {
	case types.Unknown:
		return "❓ Manual review"
	case types.Misassigned:
		if strings.Contains(row.misassignReason, "EOL") {
			return "↩️ EOL"
		}
		return "↩️ Misassigned"
	case types.NotReachable:
		if row.fixFunctionMismatch {
			return "\U0001F7E2 Affected not Impacted"
		}
		return "\U0001F7E2 No action"
	case types.BlockedByGo:
		reason := row.misassignReason
		if row.fixVersion != "" && row.currentGo != "" {
			if reason == "Go not released" {
				return fmt.Sprintf("\U0001F7E0⏳ Blocked — Go %s not yet released", row.fixVersion)
			}
			return fmt.Sprintf("\U0001F7E0⏳ Blocked — downstream Go %s, fix needs %s (bump Containerfile)", row.currentGo, row.fixVersion)
		} else if row.fixVersion != "" {
			return fmt.Sprintf("\U0001F7E0⏳ Blocked — fix needs Go %s", row.fixVersion)
		}
		return "\U0001F7E0⏳ Blocked — waiting for Go version bump"
	case types.FixableNow:
		return buildFixAction(row.cveID, row.version, latestVer, cveVersions, row.cvss, row.fixVersion, row.currentGo, row.pkg, row.installedVersion)
	default:
		return "❓ Manual review"
	}
}

func buildPerVersionAction(subRows []combinedRow, latestVer string, cveVersions map[string][]string) string {
	type versionFix struct {
		version, currentGo, fixVersion string
	}
	seen := map[string]bool{}
	var fixes []versionFix
	for _, r := range subRows {
		if seen[r.version] || r.version == "main" {
			continue
		}
		seen[r.version] = true
		if r.currentGo != "" && r.fixVersion != "" {
			fixes = append(fixes, versionFix{r.version, r.currentGo, r.fixVersion})
		}
	}
	if len(fixes) <= 1 {
		return ""
	}
	allSameGo := true
	for i := 1; i < len(fixes); i++ {
		if fixes[i].currentGo != fixes[0].currentGo {
			allSameGo = false
			break
		}
	}
	if allSameGo {
		return ""
	}
	var parts []string
	for _, f := range fixes {
		if isStdlibPackage(subRows[0].pkg) {
			parts = append(parts, fmt.Sprintf("%s (Go %s→%s)", f.version, f.currentGo, f.fixVersion))
		} else {
			parts = append(parts, fmt.Sprintf("%s (%s→%s)", f.version, f.currentGo, f.fixVersion))
		}
	}
	return "\U0001F534\U0001F527 Fix on " + strings.Join(parts, ", ")
}

func isStdlibPackage(pkg string) bool {
	return pkg != "" && !strings.Contains(pkg, ".")
}

func buildFixAction(cveID, version, latestVer string, cveVersions map[string][]string, cvss float64, fixVersion, currentGo, pkg, installedVersion string) string {
	isQualified := cvss >= 7.0

	operatorName := ""
	key := strings.ToLower(scanComponent)
	if cfg := getConfig().Components[key]; cfg.OperatorName != "" {
		operatorName = cfg.OperatorName
	}

	versions := cveVersions[cveID]
	var qualified []string
	var skipped []string
	seen := map[string]bool{}
	for _, v := range versions {
		if v == "main" {
			continue
		}
		if seen[v] {
			continue
		}
		seen[v] = true

		ver := strings.TrimPrefix(v, "v")

		if operatorName != "" {
			phase := lifecycle.LookupSupportPhase(lifecycle.LookupOCPVersion(operatorName, v))
			if phase == types.PhaseEOL {
				continue
			}
			isFullSupport := phase == types.PhaseGA
			if !isFullSupport && !isQualified {
				skipped = append(skipped, ver)
				continue
			}
		}
		qualified = append(qualified, ver)
	}

	if len(qualified) == 0 && len(skipped) > 0 {
		return "\U0001F7E2 Skip (Moderate)"
	}

	fixHint := ""
	needsGoBump := currentGo != "" && fixVersion != "" && isStdlibPackage(pkg) && compareVersionStrings(fixVersion, currentGo) > 0
	if fixVersion != "" {
		if isStdlibPackage(pkg) {
			if currentGo != "" {
				fixHint = " (Go " + currentGo + " → " + fixVersion + ")"
			} else {
				fixHint = " (Go → " + fixVersion + ")"
			}
		} else {
			shortPkg := pkg
			if i := strings.LastIndex(pkg, "/"); i >= 0 {
				shortPkg = pkg[i+1:]
			}
			if installedVersion != "" {
				fixHint = " (" + shortPkg + " " + installedVersion + " → " + fixVersion + ")"
			} else {
				fixHint = " (" + shortPkg + " → " + fixVersion + ")"
			}
		}
	}
	if needsGoBump {
		fixHint += " ⚠️ bump go.mod+Containerfile"
	}

	if len(qualified) == 0 {
		return "\U0001F534\U0001F527 Fix latest" + fixHint
	}
	sort.Slice(qualified, func(i, j int) bool {
		return compareVersionStrings(qualified[i], qualified[j]) < 0
	})
	action := "\U0001F534\U0001F527 Fix on " + strings.Join(qualified, ", ") + fixHint
	if len(skipped) > 0 {
		action += " (skip " + strings.Join(skipped, ", ") + " — Moderate)"
	}
	return action
}

func colorForAction(action string) string {
	switch {
	case strings.HasPrefix(action, "\U0001F534"):
		return colorCrit
	case strings.HasPrefix(action, "\U0001F7E0"):
		return colorHigh
	case strings.HasPrefix(action, "\U0001F7E2"):
		return colorLow
	case strings.HasPrefix(action, "↩"):
		return colorNull
	case strings.HasPrefix(action, "❓"):
		return colorMed
	default:
		return colorString
	}
}

func actionRank(row combinedRow) int {
	action := buildAction(row, "", nil)
	switch {
	case strings.Contains(action, "Fix"):
		return 0
	case strings.Contains(action, "Blocked"):
		return 1
	case strings.Contains(action, "No action"):
		return 2
	case strings.Contains(action, "Affected"):
		return 3
	case strings.Contains(action, "Skip"):
		return 4
	case strings.Contains(action, "Manual"):
		return 5
	case strings.Contains(action, "EOL"):
		return 6
	case strings.Contains(action, "Misassigned"):
		return 7
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
		ai := actionRank(rows[i])
		aj := actionRank(rows[j])
		if ai != aj {
			return ai < aj
		}
		pi := priorityOrder[rows[i].priority]
		pj := priorityOrder[rows[j].priority]
		if pi != pj {
			return pi < pj
		}
		if rows[i].cvss != rows[j].cvss {
			return rows[i].cvss > rows[j].cvss
		}
		ri := reachOrder[rows[i].reachability]
		rj := reachOrder[rows[j].reachability]
		if ri != rj {
			return ri < rj
		}
		vi := compareVersionStrings(rows[i].version, rows[j].version)
		if vi != 0 {
			return vi > 0
		}
		sti := statusRank(rows[i].status)
		stj := statusRank(rows[j].status)
		return sti < stj
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
		return strings.TrimPrefix(v, "v")
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
		if at := strings.LastIndex(filename, "@"); at > 0 {
			filename = filename[:at]
		}
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

func extractCurrentGo(r *types.Result) string {
	if ba := r.Analysis.ReleaseBranch; ba != nil {
		if ba.Downstream != nil && ba.Downstream.GoVersion != "" {
			return bareVersion(ba.Downstream.GoVersion)
		}
		return bareVersion(ba.Upstream.GoVersion)
	}
	if fu := r.Analysis.FixUpstream; fu != nil {
		return bareVersion(fu.GoVersion)
	}
	return ""
}

func bareVersion(s string) string {
	if i := strings.Index(s, " ("); i > 0 {
		s = s[:i]
	}
	return strings.TrimPrefix(s, "go")
}

func shortFixVersion(fv string) string {
	if fv == "" {
		return ""
	}
	if i := strings.Index(fv, " ("); i > 0 {
		fv = fv[:i]
	}
	if strings.HasPrefix(fv, "http") {
		return ""
	}
	return fv
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
	case types.Unknown:
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
	scanCmd.Flags().BoolVar(&scanIncludeBugs, "include-bugs", false, "Include Bug-type tickets (default: Vulnerability only)")
	scanCmd.Flags().BoolVar(&scanShort, "short", false, "Print compact summary table instead of full JSON")
	scanCmd.Flags().BoolVar(&scanDiscover, "discover", false, "Run govulncheck-only discovery (skip Jira assessment)")
	scanCmd.Flags().StringVar(&scanSince, "since", "", "Filter tickets by creation date (e.g., 1w, 30d, 1y, or 2025-01-01)")
	scanCmd.Flags().BoolVar(&scanTrivy, "trivy", true, "Run Trivy vulnerability scan (use --trivy=false to disable)")
	scanCmd.Flags().BoolVar(&scanFix, "fix", false, "Auto-fix Fixable Now tickets (use with --dry-run for preview)")
	scanCmd.Flags().StringVar(&scanCommit, "commit", "", "Pin repo checkout to a specific commit SHA")
	scanCmd.Flags().StringVar(&scanGoVersion, "go-version", "", "Downstream Go version (skips GitLab Containerfile fetch)")
	scanCmd.Flags().StringVar(&scanFormat, "format", "", "Output format: html (writes colored HTML table to stdout)")
	scanCmd.Flags().BoolVar(&scanDetectOnly, "detect-only", false, "Output JSON findings without fix or display")
	scanCmd.Flags().BoolVar(&scanVerbose, "verbose", false, "Include verbose details in HTML output (call-path diagrams)")
	scanCmd.Flags().BoolVar(&scanBlame, "blame", false, "Annotate call paths with git blame commit SHAs (adds latency)")
	rootCmd.AddCommand(scanCmd)
}
