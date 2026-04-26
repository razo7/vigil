package assess

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/razo7/vigil/pkg/classify"
	"github.com/razo7/vigil/pkg/goversion"
	"github.com/razo7/vigil/pkg/jira"
	"github.com/razo7/vigil/pkg/types"
)

const version = "0.1.0"

func Run(ctx context.Context, opts Options) (*types.Result, error) {
	jiraClient, err := jira.NewClient()
	if err != nil {
		return nil, fmt.Errorf("creating Jira client: %w", err)
	}

	ticket, err := jiraClient.FetchTicket(opts.TicketID)
	if err != nil {
		return nil, fmt.Errorf("fetching ticket: %w", err)
	}

	if ticket.CVEID == "" {
		return nil, fmt.Errorf("no CVE ID found in ticket %s", opts.TicketID)
	}

	repoPath := opts.RepoPath
	if repoPath == "" {
		repoPath = "."
	}
	repoPath, _ = filepath.Abs(repoPath)

	operatorName := deriveOperatorName(ticket.Component)

	goMod, err := goversion.ReadGoMod(repoPath)
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}
	currentGo := goMod.EffectiveVersion()

	isGoVuln := isGoRelatedCVE(ticket)
	var vulnEntry *goversion.VulnEntry

	if isGoVuln {
		vulnResult, err := goversion.RunGovulncheck(repoPath)
		if err != nil {
			return nil, fmt.Errorf("running govulncheck: %w", err)
		}
		vulnEntry = findMatchingVuln(vulnResult, ticket.CVEID)
	}

	cveSource := fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", ticket.CVEID)

	input := classify.Input{
		IsGoVuln:       isGoVuln,
		CurrentGo:      currentGo,
		DownstreamGo:   currentGo, // POC: fetch from downstream Containerfile in production
		ImageName:      ticket.ImageName,
		OperatorName:   operatorName,
		AffectsVersion: ticket.OperatorVersion,
	}

	if vulnEntry != nil {
		input.IsReachable = vulnEntry.Reachable
		input.IsPackageLevel = !vulnEntry.ModuleOnly && !vulnEntry.Reachable
		input.FixGoVersion = vulnEntry.FixVersion
	}

	classification, priority, misassignReason := classify.Classify(input)

	result := &types.Result{
		TicketID:        opts.TicketID,
		CVEID:           ticket.CVEID,
		CVESource:       cveSource,
		Classification:  classification,
		Priority:        priority,
		OperatorVersion: ticket.OperatorVersion,
		CurrentGo:       currentGo,
		DownstreamGo:    currentGo, // POC: fetch from downstream Containerfile in production
		Operator:        operatorName,
		AssessedAt:      time.Now().UTC(),
		Version:         version,
		MisassignReason: misassignReason,
	}

	if vulnEntry != nil {
		result.VulnID = vulnEntry.ID
		result.Package = vulnEntry.Package
		result.FixVersion = vulnEntry.FixVersion
		result.CallPath = vulnEntry.CallPath
		if vulnEntry.Reachable {
			result.Reachability = "REACHABLE"
		} else if !vulnEntry.ModuleOnly {
			result.Reachability = "PACKAGE-LEVEL"
		} else {
			result.Reachability = "MODULE-LEVEL"
		}
	}

	if !isGoVuln {
		result.Package = extractNonGoPackage(ticket)
		result.Reachability = "N/A (non-Go)"
	}

	result.Recommendation = generateRecommendation(result)

	return result, nil
}

func deriveOperatorName(component string) string {
	// POC: hardcoded mapping. Production should use live lookup from Jira component metadata.
	nameMap := map[string]string{
		"fence agents remediation":     "fence-agents-remediation",
		"self node remediation":        "self-node-remediation",
		"node healthcheck controller":  "node-healthcheck-controller",
		"node maintenance operator":    "node-maintenance-operator",
		"machine deletion remediation": "machine-deletion-remediation",
	}

	lower := strings.ToLower(component)
	for key, val := range nameMap {
		if strings.Contains(lower, key) {
			return val
		}
	}

	return strings.ToLower(strings.ReplaceAll(component, " ", "-"))
}

func isGoRelatedCVE(ticket *jira.TicketInfo) bool {
	lower := strings.ToLower(ticket.Summary)

	nonGoIndicators := []string{"urllib3", "python", "pip", "setuptools", "requests"}
	for _, indicator := range nonGoIndicators {
		if strings.Contains(lower, indicator) {
			return false
		}
	}

	return true
}

func findMatchingVuln(result *goversion.VulncheckResult, cveID string) *goversion.VulnEntry {
	if result == nil {
		return nil
	}
	for i := range result.Vulns {
		if strings.Contains(result.Vulns[i].ID, cveID) {
			return &result.Vulns[i]
		}
		for _, alias := range result.Vulns[i].Aliases {
			if alias == cveID {
				return &result.Vulns[i]
			}
		}
	}
	return nil
}

func extractNonGoPackage(ticket *jira.TicketInfo) string {
	lower := strings.ToLower(ticket.Summary)
	packages := []string{"urllib3", "requests", "setuptools", "pip"}
	for _, pkg := range packages {
		if strings.Contains(lower, pkg) {
			return pkg
		}
	}
	return "unknown"
}

func generateRecommendation(r *types.Result) string {
	switch r.Classification {
	case types.FixableNow:
		if r.FixVersion != "" {
			return fmt.Sprintf("Dependency or Go version bump to %s available. Create fix PR.", r.FixVersion)
		}
		return "Fix available. Create fix PR with dependency bump."
	case types.BlockedByGo:
		return fmt.Sprintf("Go version bump to %s required. Currently blocked by downstream base image. Weekly check enabled.", r.FixVersion)
	case types.NotReachable:
		return "Vulnerable code path not called. Low priority — bump if easy, otherwise document."
	case types.NotGo:
		return fmt.Sprintf("Non-Go vulnerability in %s. Requires manual review of container image dependencies.", r.Package)
	case types.Misassigned:
		return fmt.Sprintf("Ticket appears misassigned: %s. Recommend reassignment to correct component.", r.MisassignReason)
	default:
		return "Manual review required."
	}
}
