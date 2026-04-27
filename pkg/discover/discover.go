package discover

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/razo7/vigil/pkg/assess"
	"github.com/razo7/vigil/pkg/classify"
	"github.com/razo7/vigil/pkg/cve"
	"github.com/razo7/vigil/pkg/goversion"
	"github.com/razo7/vigil/pkg/jira"
	"github.com/razo7/vigil/pkg/types"
)

type Options struct {
	RepoPath  string
	Component string
	JQL       string
}

var componentFullName = map[string]string{
	"far": "Fence Agents Remediation",
	"snr": "Self Node Remediation",
	"nhc": "Node Healthcheck",
	"nmo": "Node Maintenance Operator",
	"mdr": "Machine Deletion Remediation",
	"sbr":         "Storage-based Remediation",
	"nhc-console": "Node Remediation Console",
}

func Run(ctx context.Context, opts Options) (*types.DiscoverResult, error) {
	repoPath := opts.RepoPath
	if repoPath == "" {
		fullName, ok := componentFullName[strings.ToLower(opts.Component)]
		if !ok {
			return nil, fmt.Errorf("unknown component %q; provide --repo-path", opts.Component)
		}
		url := assess.DeriveRepoURL(fullName)
		if url == "" {
			return nil, fmt.Errorf("no repo URL for component %q", opts.Component)
		}
		resolved, cleanup, err := assess.ResolveRepoPath(url)
		if err != nil {
			return nil, fmt.Errorf("resolving repo: %w", err)
		}
		if cleanup != nil {
			defer cleanup()
		}
		repoPath = resolved
	}

	goMod, err := goversion.ReadGoMod(repoPath)
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}
	currentGo := goMod.EffectiveVersion()

	fmt.Fprintf(os.Stderr, "Running govulncheck on %s (Go %s)...\n", repoPath, currentGo)
	vulnResult, err := goversion.RunGovulncheck(repoPath)
	if err != nil {
		return nil, fmt.Errorf("running govulncheck: %w", err)
	}

	ticketMap := buildTicketMap(opts)

	var vulns []types.DiscoveredVuln
	for _, entry := range vulnResult.Vulns {
		dv := types.DiscoveredVuln{
			VulnID:         entry.ID,
			Description:    entry.Summary,
			CVEIDs:         entry.Aliases,
			Package:        entry.Package,
			PackageSource:  "govulncheck",
			Language:       "Go",
			LanguageSource: "govulncheck",
			Reachability:   goversion.ReachabilityLabel(&entry),
			FixVersion:     entry.FixVersion,
			CallPaths:      entry.CallPaths,
		}

		matchedTickets := findMatchingTickets(entry.Aliases, ticketMap)
		if len(matchedTickets) > 0 {
			dv.HasTicket = true
			var ids []string
			for _, t := range matchedTickets {
				ids = append(ids, t.Key)
			}
			dv.TicketID = strings.Join(ids, ", ")
			dv.TicketStatus = matchedTickets[0].Status
			dv.Source = "Both"
		} else {
			dv.Source = "Scan"
		}

		if len(entry.Aliases) > 0 {
			cveInfo, err := cve.FetchCVSSScore(entry.Aliases[0])
			if err == nil && cveInfo != nil {
				dv.Severity = cveInfo.Score
				dv.SeverityLabel = cveInfo.Severity
			}
		}

		input := classify.Input{
			IsGoVuln:       true,
			IsReachable:    entry.Reachable && !entry.TestOnly,
			IsPackageLevel: !entry.ModuleOnly && !entry.Reachable,
			TestOnly:       entry.TestOnly,
			FixGoVersion:   entry.FixVersion,
			CurrentGo:      currentGo,
			CVSS:           dv.Severity,
		}
		classification, priority, _ := classify.Classify(input)
		dv.Classification = classification
		dv.Priority = priority

		if dv.Reachability == "PACKAGE-LEVEL" && entry.Package != "" {
			if chain := runGoModWhy(repoPath, entry.Package); chain != "" {
				dv.ImportChain = chain
			}
		}

		vulns = append(vulns, dv)
	}

	SortVulns(vulns)

	withTicket := 0
	for _, v := range vulns {
		if v.HasTicket {
			withTicket++
		}
	}

	return &types.DiscoverResult{
		Component:  opts.Component,
		RepoPath:   repoPath,
		GoVersion:  currentGo,
		TotalVulns: len(vulns),
		WithTicket: withTicket,
		NoTicket:   len(vulns) - withTicket,
		Vulns:      vulns,
		AssessedAt: time.Now().UTC(),
	}, nil
}

func buildTicketMap(opts Options) map[string]*jira.TicketInfo {
	if opts.Component == "" && opts.JQL == "" {
		return nil
	}

	jql := opts.JQL
	if jql == "" {
		key := strings.ToLower(opts.Component)
		fullName, ok := componentFullName[key]
		if !ok {
			return nil
		}
		jql = fmt.Sprintf(
			`project in (RHWA, ECOPROJECT) AND issuetype in (Vulnerability, Bug) AND component in ("%s") ORDER BY created DESC`,
			fullName,
		)
	}

	tickets, err := jira.SearchTicketsCLI(jql)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: jira CLI search failed (%v), falling back to REST API\n", err)
		jiraClient, clientErr := jira.NewClient()
		if clientErr != nil {
			fmt.Fprintf(os.Stderr, "WARNING: cannot create Jira client: %v\n", clientErr)
			return nil
		}
		tickets, err = jiraClient.SearchTickets(jql)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: Jira search failed: %v\n", err)
			return nil
		}
	}

	m := make(map[string]*jira.TicketInfo, len(tickets))
	for i := range tickets {
		if tickets[i].CVEID != "" {
			m[tickets[i].CVEID] = &tickets[i]
		}
	}
	return m
}

func findMatchingTickets(aliases []string, ticketMap map[string]*jira.TicketInfo) []*jira.TicketInfo {
	if ticketMap == nil {
		return nil
	}
	var matched []*jira.TicketInfo
	seen := make(map[string]bool)
	for _, alias := range aliases {
		if t, ok := ticketMap[alias]; ok && !seen[t.Key] {
			matched = append(matched, t)
			seen[t.Key] = true
		}
	}
	return matched
}

func ticketStatusRank(status string) int {
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

func SortVulns(vulns []types.DiscoveredVuln) {
	sourceOrder := map[string]int{
		"Both": 0,
		"Jira": 1,
		"Scan": 2,
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
		"REACHABLE":     0,
		"TEST-ONLY":     1,
		"PACKAGE-LEVEL": 2,
		"MODULE-LEVEL":  3,
		"UNKNOWN":       4,
	}

	sort.Slice(vulns, func(i, j int) bool {
		si := sourceOrder[vulns[i].Source]
		sj := sourceOrder[vulns[j].Source]
		if si != sj {
			return si < sj
		}
		sti := ticketStatusRank(vulns[i].TicketStatus)
		stj := ticketStatusRank(vulns[j].TicketStatus)
		if sti != stj {
			return sti < stj
		}
		pi := priorityOrder[vulns[i].Priority]
		pj := priorityOrder[vulns[j].Priority]
		if pi != pj {
			return pi < pj
		}
		ri := reachOrder[vulns[i].Reachability]
		rj := reachOrder[vulns[j].Reachability]
		if ri != rj {
			return ri < rj
		}
		return vulns[i].Severity > vulns[j].Severity
	})
}

func MatchedCVEIDs(result *types.DiscoverResult) map[string]string {
	m := make(map[string]string)
	for _, v := range result.Vulns {
		for _, cveID := range v.CVEIDs {
			m[cveID] = v.Source
		}
	}
	return m
}

func runGoModWhy(repoPath, pkg string) string {
	cmd := exec.Command("go", "mod", "why", "-m", pkg)
	cmd.Dir = repoPath
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	var chain []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "(") {
			continue
		}
		chain = append(chain, line)
	}
	if len(chain) == 0 {
		return ""
	}
	return strings.Join(chain, " → ")
}
