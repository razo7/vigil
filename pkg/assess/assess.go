package assess

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

	branchName := "main"
	if usedWorktree && ticket.OperatorVersion != "" {
		branchName = goversion.ReleaseBranch(ticket.OperatorVersion)
	}

	downstreamGo := currentGo
	dsInfo, err := downstream.FetchGoVersionForOperator(operatorName, ticket.ImageName, ticket.OperatorVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: downstream Go version not available: %v\n", err)
	} else if dsInfo.GoVersion != "" {
		downstreamGo = dsInfo.GoVersion
	}

	var dsComponent *downstream.DownstreamComponent
	if ticket.OperatorVersion != "" {
		dsComponent, _ = downstream.LookupDownstreamComponent(operatorName, ticket.OperatorVersion)
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

	cveID := fmt.Sprintf("%s (https://www.cve.org/CVERecord?id=%s)", ticket.CVEID, ticket.CVEID)

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

	// Build branch analysis for the scanned branch
	ba := buildBranchAnalysis(branchName, currentGo,
		buildGoModLink(ticket.Component, branchName, goMod.EffectiveVersionLine()),
		vulnEntry, isGoVuln, ticket, cveInfo)

	// Populate downstream info
	ba.Downstream = buildDownstreamInfo(operatorName, dsInfo, dsComponent)

	result := &types.Result{
		Source: types.SourceInfo{
			TicketID:          fmt.Sprintf("%s (%s/browse/%s)", opts.TicketID, jiraClient.BaseURL(), opts.TicketID),
			Operator:          operatorName,
			OperatorVersion:   ticket.OperatorVersion,
			Reporter:          ticket.Reporter,
			Assignee:          ticket.Assignee,
			DueDate:           ticket.DueDate,
			JiraPriority:      ticket.JiraPriority,
			Labels:            strings.Join(ticket.Labels, ", "),
			AffectsVersions:   strings.Join(ticket.AffectsVersions, ", "),
			TicketFixVersions: strings.Join(ticket.FixVersions, ", "),
			OCPSupport:        lifecycle.BuildOCPSupport(operatorName, ticket.OperatorVersion),
		},
		Vulnerability: types.VulnInfo{
			CVEID:         cveID,
			Severity:      severity,
			SeverityLabel: severityLabel,
		},
		Recommendation: types.RecommendationInfo{
			Classification:  classification,
			Priority:        priority,
			MisassignReason: misassignReason,
		},
		AssessedAt: time.Now().UTC(),
		Version:    version,
	}

	if cveInfo != nil {
		result.Vulnerability.CWE = cveInfo.CWE
		result.Vulnerability.CWEDescription = cveInfo.CWEDescription
		result.Vulnerability.References = filterGoReferences(cveInfo.References)
	}

	if usedWorktree {
		result.Analysis.ReleaseBranch = ba
		if isGoVuln {
			result.Analysis.LatestBranch = assessLatestBranch(repoPath, ticket.CVEID, ticket.Component, operatorName, ticket.ImageName)
		}
	} else {
		result.Analysis.LatestBranch = ba
	}

	result.Recommendation.Action = generateRecommendation(result)

	return result, nil
}

func buildBranchAnalysis(branch, goVersion, goModLink string, vulnEntry *goversion.VulnEntry, isGoVuln bool, ticket *jira.TicketInfo, cveInfo *cve.CVEInfo) *types.BranchAnalysis {
	ba := &types.BranchAnalysis{
		Upstream: types.UpstreamInfo{
			Branch:    branch,
			GoVersion: goVersion,
			GoModLink: goModLink,
		},
	}

	if vulnEntry != nil {
		ba.VulnID = vulnEntry.ID
		ba.Package = vulnEntry.Package
		ba.FixVersion = vulnEntry.FixVersion
		ba.AffectedGoVersions = formatAffectedVersions(vulnEntry.IntroducedVersion, vulnEntry.FixVersion)
		ba.CallPath = vulnEntry.CallPath
		if vulnEntry.Reachable {
			ba.Reachability = "REACHABLE"
		} else if !vulnEntry.ModuleOnly {
			ba.Reachability = "PACKAGE-LEVEL (imported but no call path)"
		} else {
			ba.Reachability = "MODULE-LEVEL (in go.mod but package not imported)"
		}
	} else if isGoVuln {
		ba.Reachability = "UNKNOWN (CVE not in Go vuln DB)"
		if pkg := jira.ExtractGoPackage(ticket.Summary); pkg != "" {
			ba.Package = fmt.Sprintf("%s (from ticket summary)", pkg)
		} else if cveInfo != nil {
			if pkg := jira.ExtractGoPackage(cveInfo.Description); pkg != "" {
				ba.Package = fmt.Sprintf("%s (from CVE description)", pkg)
			}
		}
	} else {
		ba.Package = fmt.Sprintf("%s (non-Go)", extractNonGoPackage(ticket))
		ba.Reachability = "N/A (non-Go)"
	}

	if ba.VulnID == "" && cveInfo != nil {
		if vulnID := extractVulnIDFromRefs(cveInfo.References); vulnID != "" {
			ba.VulnID = vulnID
		}
	}

	return ba
}

func buildDownstreamInfo(operatorName string, dsInfo *downstream.ContainerfileInfo, dsComponent *downstream.DownstreamComponent) *types.DownstreamInfo {
	ds := &types.DownstreamInfo{}
	populated := false

	if dsInfo != nil && dsInfo.GoVersion != "" {
		ds.GoVersion = dsInfo.GoVersion
		ds.GoLink = buildDownstreamLink(operatorName, dsInfo)
		populated = true
	}

	if dsComponent != nil {
		ds.ComponentName = dsComponent.Name
		ds.ComponentURL = dsComponent.CatalogURL
		ds.RHELBase = dsComponent.RHELBase
		populated = true
	}

	if !populated {
		return nil
	}
	return ds
}

func assessLatestBranch(repoPath, cveID, component, operatorName, imageName string) *types.BranchAnalysis {
	goMod, err := goversion.ReadGoMod(repoPath)
	if err != nil {
		return nil
	}

	ba := &types.BranchAnalysis{
		Upstream: types.UpstreamInfo{
			Branch:    "main",
			GoVersion: goMod.EffectiveVersion(),
			GoModLink: buildGoModLink(component, "main", goMod.EffectiveVersionLine()),
		},
	}

	dsInfo, err := downstream.FetchGoVersion(operatorName, imageName, "main")
	if err == nil && dsInfo.GoVersion != "" {
		ba.Downstream = &types.DownstreamInfo{
			GoVersion: dsInfo.GoVersion,
			GoLink:    buildDownstreamLink(operatorName, dsInfo),
		}
	}

	vulnResult, err := goversion.RunGovulncheck(repoPath)
	if err != nil {
		return ba
	}

	entry := findMatchingVuln(vulnResult, cveID)
	if entry == nil {
		ba.Reachability = "NOT-FOUND (CVE not in Go vuln DB)"
		return ba
	}

	ba.VulnID = entry.ID
	ba.Package = entry.Package
	ba.FixVersion = entry.FixVersion
	ba.AffectedGoVersions = formatAffectedVersions(entry.IntroducedVersion, entry.FixVersion)
	ba.CallPath = entry.CallPath

	if entry.Reachable {
		ba.Reachability = "REACHABLE"
	} else if !entry.ModuleOnly {
		ba.Reachability = "PACKAGE-LEVEL (imported but no call path)"
	} else {
		ba.Reachability = "MODULE-LEVEL (in go.mod but package not imported)"
	}

	return ba
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

var goVulnIDRe = regexp.MustCompile(`GO-\d{4}-\d+`)

func filterGoReferences(refs []string) []string {
	var goRefs []string
	for _, ref := range refs {
		if strings.Contains(ref, "pkg.go.dev/vuln/") ||
			strings.Contains(ref, "go-review.googlesource.com") ||
			strings.Contains(ref, "groups.google.com/g/golang-announce") ||
			strings.Contains(ref, "go.dev/issue/") ||
			strings.Contains(ref, "github.com/golang/go/issues/") {
			goRefs = append(goRefs, ref)
		}
	}
	return goRefs
}

func extractVulnIDFromRefs(refs []string) string {
	for _, ref := range refs {
		if m := goVulnIDRe.FindString(ref); m != "" {
			return m
		}
	}
	return ""
}

func formatAffectedVersions(introduced, fixed string) string {
	if introduced == "" && fixed == "" {
		return ""
	}
	if fixed != "" {
		if introduced != "" && introduced != "0" {
			return fmt.Sprintf(">= %s, fixed in %s", introduced, fixed)
		}
		return fmt.Sprintf("fixed in %s", fixed)
	}
	return fmt.Sprintf(">= %s", introduced)
}

func buildGoModLink(component, branch string, line int) string {
	repoURL := deriveRepoURL(component)
	if repoURL == "" || line == 0 {
		return ""
	}
	repoURL = strings.TrimSuffix(repoURL, ".git")
	return fmt.Sprintf("%s/blob/%s/go.mod#L%d", repoURL, branch, line)
}

func buildDownstreamLink(operatorName string, dsInfo *downstream.ContainerfileInfo) string {
	if dsInfo.GoVersionLine == 0 || dsInfo.FilePath == "" {
		return ""
	}
	host := os.Getenv("GITLAB_HOST")
	if host == "" {
		host = "https://gitlab.cee.redhat.com"
	}
	return fmt.Sprintf("%s/dragonfly/%s/-/blob/%s/%s#L%d",
		host, operatorName, dsInfo.Branch, dsInfo.FilePath, dsInfo.GoVersionLine)
}

func primaryBranch(r *types.Result) *types.BranchAnalysis {
	if r.Analysis.ReleaseBranch != nil {
		return r.Analysis.ReleaseBranch
	}
	return r.Analysis.LatestBranch
}

func generateRecommendation(r *types.Result) string {
	ba := primaryBranch(r)
	fixVersion := ""
	pkg := ""
	if ba != nil {
		fixVersion = ba.FixVersion
		pkg = ba.Package
	}

	switch r.Recommendation.Classification {
	case types.FixableNow:
		if fixVersion != "" {
			return fmt.Sprintf("Dependency or Go version bump to %s available. Create fix PR.", fixVersion)
		}
		return "Fix available. Create fix PR with dependency bump."
	case types.BlockedByGo:
		return fmt.Sprintf("Go version bump to %s required. Currently blocked by downstream base image.", fixVersion)
	case types.NotReachable:
		return "Vulnerable code path not called. Low priority — bump if easy, otherwise document."
	case types.NotGo:
		return fmt.Sprintf("Non-Go vulnerability in %s. Requires manual review of container image dependencies.", pkg)
	case types.Misassigned:
		return fmt.Sprintf("Ticket appears misassigned: %s. Recommend reassignment to correct component.", r.Recommendation.MisassignReason)
	default:
		return "Manual review required."
	}
}
