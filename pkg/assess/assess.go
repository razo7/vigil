package assess

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/razo7/vigil/pkg/classify"
	"github.com/razo7/vigil/pkg/cve"
	"github.com/razo7/vigil/pkg/downstream"
	"github.com/razo7/vigil/pkg/goversion"
	"github.com/razo7/vigil/pkg/jira"
	"github.com/razo7/vigil/pkg/lifecycle"
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

	operatorName := deriveOperatorName(ticket.Component)

	repoInput := opts.RepoPath
	if repoInput == "" {
		repoInput = deriveRepoURL(ticket.Component)
		if repoInput == "" {
			repoInput = "."
		}
	}

	repoPath, repoCleanup, err := resolveRepoPath(repoInput)
	if err != nil {
		return nil, fmt.Errorf("resolving repo path: %w", err)
	}
	if repoCleanup != nil {
		defer repoCleanup()
	}
	repoPath, _ = filepath.Abs(repoPath)

	scanPath := repoPath
	usedWorktree := false
	var worktreeCleanup func()

	if ticket.OperatorVersion != "" {
		branch := goversion.ReleaseBranch(ticket.OperatorVersion)
		if goversion.HasBranch(repoPath, branch) {
			wt, cleanup, err := goversion.CreateWorktree(repoPath, branch)
			if err == nil {
				scanPath = wt
				worktreeCleanup = cleanup
				usedWorktree = true
			}
		}
	}
	if worktreeCleanup != nil {
		defer worktreeCleanup()
	}

	goMod, err := goversion.ReadGoMod(scanPath)
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}
	currentGo := goMod.EffectiveVersion()

	downstreamGo := currentGo
	dsInfo, err := downstream.FetchGoVersion(operatorName, ticket.ImageName, "")
	if err == nil && dsInfo.GoVersion != "" {
		downstreamGo = dsInfo.GoVersion
	}

	isGoVuln := isGoRelatedCVE(ticket)
	var vulnEntry *goversion.VulnEntry

	if isGoVuln {
		vulnResult, err := goversion.RunGovulncheck(scanPath)
		if err != nil {
			return nil, fmt.Errorf("running govulncheck: %w", err)
		}
		vulnEntry = findMatchingVuln(vulnResult, ticket.CVEID)
	}

	cveSource := fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", ticket.CVEID)

	var severity float64
	var severityLabel string
	cveInfo, err := cve.FetchCVSSScore(ticket.CVEID)
	if err == nil && cveInfo != nil {
		severity = cveInfo.Score
		severityLabel = cveInfo.Severity
		if !isGoVuln {
			// already detected as non-Go from ticket summary
		} else if isNonGoDescription(cveInfo.Description) {
			isGoVuln = false
		}
	}

	input := classify.Input{
		IsGoVuln:       isGoVuln,
		CurrentGo:      currentGo,
		DownstreamGo:   downstreamGo,
		ImageName:      ticket.ImageName,
		OperatorName:   operatorName,
		AffectsVersion: ticket.OperatorVersion,
		CVSS:           severity,
	}

	ocpVersion := lifecycle.LookupOCPVersion(operatorName, ticket.OperatorVersion)
	supportPhase := lifecycle.LookupSupportPhase(ocpVersion)
	input.SupportPhase = supportPhase

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
		Severity:        severity,
		SeverityLabel:   severityLabel,
		Classification:  classification,
		Priority:        priority,
		OperatorVersion: ticket.OperatorVersion,
		OCPVersion:      ocpVersion,
		SupportPhase:    supportPhase,
		CurrentGo:       currentGo,
		DownstreamGo:    downstreamGo,
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

	if usedWorktree && isGoVuln {
		result.MainBranch = assessMainBranch(repoPath, ticket.CVEID)
	}

	result.Recommendation = generateRecommendation(result)

	return result, nil
}

func assessMainBranch(repoPath, cveID string) *types.MainBranchResult {
	goMod, err := goversion.ReadGoMod(repoPath)
	if err != nil {
		return nil
	}

	mbr := &types.MainBranchResult{
		CurrentGo: goMod.EffectiveVersion(),
	}

	vulnResult, err := goversion.RunGovulncheck(repoPath)
	if err != nil {
		return mbr
	}

	entry := findMatchingVuln(vulnResult, cveID)
	if entry == nil {
		mbr.Reachability = "NOT-FOUND"
		return mbr
	}

	mbr.VulnID = entry.ID
	mbr.Package = entry.Package
	mbr.FixVersion = entry.FixVersion
	mbr.CallPath = entry.CallPath

	if entry.Reachable {
		mbr.Reachability = "REACHABLE"
	} else if !entry.ModuleOnly {
		mbr.Reachability = "PACKAGE-LEVEL"
	} else {
		mbr.Reachability = "MODULE-LEVEL"
	}

	return mbr
}

type operatorInfo struct {
	Name    string
	RepoURL string
}

var operatorMap = map[string]operatorInfo{
	"fence agents remediation":     {Name: "fence-agents-remediation", RepoURL: "https://github.com/medik8s/fence-agents-remediation.git"},
	"self node remediation":        {Name: "self-node-remediation", RepoURL: "https://github.com/medik8s/self-node-remediation.git"},
	"node healthcheck controller":  {Name: "node-healthcheck-controller", RepoURL: "https://github.com/medik8s/node-healthcheck-operator.git"},
	"node maintenance operator":    {Name: "node-maintenance-operator", RepoURL: "https://github.com/medik8s/node-maintenance-operator.git"},
	"machine deletion remediation": {Name: "machine-deletion-remediation", RepoURL: "https://github.com/medik8s/machine-deletion-remediation.git"},
}

func deriveOperatorName(component string) string {
	lower := strings.ToLower(component)
	for key, info := range operatorMap {
		if strings.Contains(lower, key) {
			return info.Name
		}
	}
	return strings.ToLower(strings.ReplaceAll(component, " ", "-"))
}

func deriveRepoURL(component string) string {
	lower := strings.ToLower(component)
	for key, info := range operatorMap {
		if strings.Contains(lower, key) {
			return info.RepoURL
		}
	}
	return ""
}

func isGoRelatedCVE(ticket *jira.TicketInfo) bool {
	return !isNonGoDescription(ticket.Summary)
}

var nonGoIndicators = []string{
	"python", " pip ", "setuptools", "python-requests", "urllib3",
	"ply ", "ruby", "perl ", "java ", "node.js", " npm ",
	"php ", "c library", "glibc", "libxml",
}

func isNonGoDescription(desc string) bool {
	lower := strings.ToLower(desc)
	for _, indicator := range nonGoIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
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
