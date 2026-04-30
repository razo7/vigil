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

const version = "0.0.2"

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

	operatorName := DeriveOperatorName(ticket.Component)

	if ticket.OperatorVersion == "" {
		for _, av := range ticket.AffectsVersions {
			if ver := lifecycle.LookupOperatorVersionFromRHWA(operatorName, av); ver != "" {
				ticket.OperatorVersion = ver
				ticket.OperatorVersionSource = "rhwa-version"
				break
			}
		}
	}

	repoInput := opts.RepoPath
	if repoInput == "" {
		repoInput = DeriveRepoURL(ticket.Component)
		if repoInput == "" {
			repoInput = "."
		}
	}

	repoPath, repoCleanup, err := ResolveRepoPath(repoInput)
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
		vulnResult, err := goversion.RunGovulncheckWithVersion(scanPath, currentGo)
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
		if !isGoVuln && isExplicitlyGo(cveInfo.Description) {
			isGoVuln = true
		} else if isGoVuln && !isExplicitlyGo(ticket.Summary) && isNonGoDescription(cveInfo.Description) {
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

	var fixFunctions string
	if cveInfo != nil {
		var allRefs []string
		allRefs = append(allRefs, cveInfo.References...)
		if vulnEntry != nil && vulnEntry.ID != "" {
			if dbResult := fetchFromVulnDB(vulnEntry.ID); dbResult != nil {
				allRefs = append(allRefs, dbResult.References...)
			}
		}
		if link := extractGoReviewLink(allRefs); link != "" {
			fixFunctions = fetchFixFunctions(link)
		}
	}

	if vulnEntry != nil {
		input.IsReachable = vulnEntry.Reachable
		input.IsPackageLevel = !vulnEntry.ModuleOnly && !vulnEntry.Reachable
		input.FixGoVersion = vulnEntry.FixVersion
		if vulnEntry.Module != "" && vulnEntry.Module != "stdlib" && vulnEntry.FixVersion != "" {
			if reqGo, err := goversion.FetchModuleGoVersion(vulnEntry.Module, vulnEntry.FixVersion); err == nil && reqGo != "" {
				input.FixGoVersion = reqGo
			}
		}
		if vulnEntry.Reachable && vulnEntry.TestOnly {
			input.IsReachable = false
			input.IsPackageLevel = true
			input.TestOnly = true
		} else if vulnEntry.Reachable && fixFunctions != "" {
			if !fixFunctionsInCallPaths(fixFunctions, vulnEntry.CallPaths) {
				input.IsReachable = false
				input.IsPackageLevel = true
				input.FixFunctionMismatch = true
			}
		}
	} else if isGoVuln {
		pkg := jira.ExtractGoPackage(ticket.Summary)
		if pkg == "" && cveInfo != nil {
			pkg = jira.ExtractGoPackage(cveInfo.Description)
		}
		if pkg != "" {
			if goversion.IsPackageImported(scanPath, pkg) {
				input.IsPackageLevel = true
			}
		}
	}

	classification, priority, misassignReason := classify.Classify(input)

	// Build branch analysis for the scanned branch
	fallbackImported := vulnEntry == nil && isGoVuln && input.IsPackageLevel
	ba := buildBranchAnalysis(branchName, currentGo,
		buildGoModLink(ticket.Component, branchName, goMod.EffectiveVersionLine()),
		vulnEntry, isGoVuln, input.FixFunctionMismatch, input.TestOnly, fallbackImported)

	// Populate downstream and catalog component info
	ba.Downstream, ba.CatalogComponent = buildDownstreamInfo(operatorName, dsInfo, dsComponent)

	result := &types.Result{
		Source: types.SourceInfo{
			TicketID:                fmt.Sprintf("%s (%s/browse/%s)", opts.TicketID, jiraClient.BaseURL(), opts.TicketID),
			AffectedOperatorVersion: formatOperator(operatorName, ticket.OperatorVersion, ticket.OperatorVersionSource),
			Status:                  ticket.Status,
			Resolution:              ticket.Resolution,
			Reporter:                ticket.Reporter,
			Assignee:                ticket.Assignee,
			DueDate:                 ticket.DueDate,
			Created:                 ticket.Created,
			JiraPriority:            ticket.JiraPriority,
			Labels:                  strings.Join(ticket.Labels, ", "),
			AffectsRHWAVersions:     strings.Join(ticket.AffectsVersions, ", "),
			TicketFixVersions:       strings.Join(ticket.FixVersions, ", "),
			OCPSupport:              lifecycle.BuildOCPSupport(operatorName, ticket.OperatorVersion),
		},
		Vulnerability: types.VulnInfo{
			CVEID:         cveID,
			Severity:      severity,
			SeverityLabel: severityLabel,
			Language:      detectLanguage(isGoVuln, ticket, cveDescription(cveInfo)),
		},
		Recommendation: types.RecommendationInfo{
			Classification:  classification,
			Priority:        priority,
			MisassignReason: misassignReason,
		},
		AssessedAt: time.Now().UTC(),
		Version:    version,
	}

	populateVulnMetadata(&result.Vulnerability, vulnEntry, isGoVuln, ticket, cveInfo, fixFunctions)

	if cveInfo != nil {
		result.Vulnerability.CWE = cveInfo.CWE
		result.Vulnerability.CWEDescription = cveInfo.CWEDescription
		if refs := filterGoReferences(cveInfo.References); len(refs) > 0 {
			result.Vulnerability.References = strings.Join(refs, ", ")
		}
	}

	if usedWorktree {
		result.Analysis.ReleaseBranch = ba
		if isGoVuln {
			result.Analysis.FixUpstream = assessFixUpstream(repoPath, ticket.CVEID, ticket.Component)
		}
	} else {
		result.Analysis.ReleaseBranch = ba
	}

	result.Recommendation.Action = generateRecommendation(result)

	return result, nil
}

func buildBranchAnalysis(branch, goVersion, goModLink string, vulnEntry *goversion.VulnEntry, isGoVuln bool, fixFuncMismatch bool, testOnly bool, fallbackImported bool) *types.BranchAnalysis {
	goVersionStr := goVersion
	if goModLink != "" {
		goVersionStr = fmt.Sprintf("%s (%s)", goVersion, goModLink)
	}
	ba := &types.BranchAnalysis{
		Upstream: types.UpstreamInfo{
			Branch:    branch,
			GoVersion: goVersionStr,
		},
	}

	if vulnEntry != nil {
		ba.CallPaths = vulnEntry.CallPaths
		if testOnly {
			ba.Reachability = "TEST-ONLY (reachable only through test code, not shipped binary)"
		} else if fixFuncMismatch {
			ba.Reachability = "PACKAGE-LEVEL (package imported but fix functions not in call path)"
		} else if vulnEntry.Reachable {
			ba.Reachability = "REACHABLE"
		} else if !vulnEntry.ModuleOnly {
			ba.Reachability = "PACKAGE-LEVEL (imported but no call path)"
		} else {
			ba.Reachability = "MODULE-LEVEL (in go.mod but package not imported)"
		}
	} else if isGoVuln {
		if fallbackImported {
			ba.Reachability = "PACKAGE-LEVEL (not in vuln DB, but package imported)"
		} else {
			ba.Reachability = "NOT-IMPORTED (not in vuln DB, package not found in codebase)"
		}
	} else {
		ba.Reachability = "N/A (non-Go)"
	}

	return ba
}

func populateVulnMetadata(v *types.VulnInfo, vulnEntry *goversion.VulnEntry, isGoVuln bool, ticket *jira.TicketInfo, cveInfo *cve.CVEInfo, fixFunctions string) {
	if vulnEntry != nil {
		v.VulnID = vulnEntry.ID
		v.Package = vulnEntry.Package
		v.FixVersion = vulnEntry.FixVersion
		affected := formatAffectedRanges(vulnEntry.AffectedRanges)
		if affected != "" && vulnEntry.ID != "" {
			v.AffectedGoVersions = fmt.Sprintf("%s (https://pkg.go.dev/vuln/%s)", affected, vulnEntry.ID)
		} else {
			v.AffectedGoVersions = affected
		}
	} else if isGoVuln {
		if pkg := jira.ExtractGoPackage(ticket.Summary); pkg != "" {
			v.Package = fmt.Sprintf("%s (from ticket summary)", pkg)
		} else if cveInfo != nil {
			if pkg := jira.ExtractGoPackage(cveInfo.Description); pkg != "" {
				v.Package = fmt.Sprintf("%s (from CVE description)", pkg)
			}
		}
	} else {
		desc := ""
		if cveInfo != nil {
			desc = cveInfo.Description
		}
		v.Package = fmt.Sprintf("%s (non-Go)", extractNonGoPackage(ticket, desc))
	}

	if cveInfo != nil {
		if cveInfo.Description != "" {
			v.Description = firstSentence(cveInfo.Description)
		}

		if v.VulnID == "" {
			if vulnID := extractVulnIDFromRefs(cveInfo.References); vulnID != "" {
				v.VulnID = vulnID
			}
		}

		var allRefs []string
		allRefs = append(allRefs, cveInfo.References...)

		if v.VulnID != "" && v.AffectedGoVersions == "" {
			if dbResult := fetchFromVulnDB(v.VulnID); dbResult != nil {
				allRefs = append(allRefs, dbResult.References...)
				if len(dbResult.Ranges) > 0 {
					affected := formatAffectedRanges(dbResult.Ranges)
					v.AffectedGoVersions = fmt.Sprintf("%s (https://pkg.go.dev/vuln/%s)", affected, v.VulnID)
				}
				if v.FixVersion == "" && dbResult.FixVersion != "" {
					v.FixVersion = dbResult.FixVersion
				}
			}
			if v.AffectedGoVersions == "" {
				v.AffectedGoVersions = fmt.Sprintf("https://pkg.go.dev/vuln/%s", v.VulnID)
			}
		}

		if link := extractGoReviewLink(allRefs); link != "" {
			if v.FixVersion != "" {
				v.FixVersion = fmt.Sprintf("%s (%s)", v.FixVersion, link)
			} else {
				v.FixVersion = link
			}
			if fixFunctions != "" {
				v.FixFunctions = fixFunctions
			} else {
				v.FixFunctions = fetchFixFunctions(link)
			}
		} else if fixFunctions != "" {
			v.FixFunctions = fixFunctions
		}
	}
}

func buildDownstreamInfo(operatorName string, dsInfo *downstream.ContainerfileInfo, dsComponent *downstream.DownstreamComponent) (*types.DownstreamInfo, string) {
	var ds *types.DownstreamInfo
	var catalogComponent string

	if dsInfo != nil && dsInfo.GoVersion != "" {
		ds = &types.DownstreamInfo{
			Branch: dsInfo.Branch,
		}
		link := buildDownstreamLink(operatorName, dsInfo)
		if link != "" {
			ds.GoVersion = fmt.Sprintf("%s (%s)", dsInfo.GoVersion, link)
		} else {
			ds.GoVersion = dsInfo.GoVersion
		}
	}

	if dsComponent != nil {
		if dsComponent.CatalogURL != "" {
			catalogComponent = fmt.Sprintf("%s (%s)", dsComponent.Name, dsComponent.CatalogURL)
		} else {
			catalogComponent = dsComponent.Name
		}
	}

	return ds, catalogComponent
}

func assessFixUpstream(repoPath, cveID, component string) *types.FixUpstreamInfo {
	goMod, err := goversion.ReadGoMod(repoPath)
	if err != nil {
		return nil
	}

	goVersionStr := goMod.EffectiveVersion()
	if link := buildGoModLink(component, "main", goMod.EffectiveVersionLine()); link != "" {
		goVersionStr = fmt.Sprintf("%s (%s)", goVersionStr, link)
	}
	fu := &types.FixUpstreamInfo{
		GoVersion: goVersionStr,
	}

	vulnResult, err := goversion.RunGovulncheckWithVersion(repoPath, goMod.EffectiveVersion())
	if err != nil {
		return fu
	}

	entry := findMatchingVuln(vulnResult, cveID)
	if entry == nil {
		fu.Reachability = "UNKNOWN (CVE not in Go vuln DB)"
		return fu
	}

	fu.CallPaths = entry.CallPaths

	if entry.Reachable && entry.TestOnly {
		fu.Reachability = "TEST-ONLY (reachable only through test code, not shipped binary)"
	} else if entry.Reachable {
		fu.Reachability = "REACHABLE"
	} else if !entry.ModuleOnly {
		fu.Reachability = "PACKAGE-LEVEL (imported but no call path)"
	} else {
		fu.Reachability = "MODULE-LEVEL (in go.mod but package not imported)"
	}

	return fu
}

type operatorInfo struct {
	Name    string
	RepoURL string
}

var operatorMap = map[string]operatorInfo{
	"fence agents remediation":     {Name: "fence-agents-remediation", RepoURL: "https://github.com/medik8s/fence-agents-remediation.git"},
	"self node remediation":        {Name: "self-node-remediation", RepoURL: "https://github.com/medik8s/self-node-remediation.git"},
	"node healthcheck":             {Name: "node-healthcheck-operator", RepoURL: "https://github.com/medik8s/node-healthcheck-operator.git"},
	"node maintenance operator":    {Name: "node-maintenance-operator", RepoURL: "https://github.com/medik8s/node-maintenance-operator.git"},
	"machine deletion remediation": {Name: "machine-deletion-remediation", RepoURL: "https://github.com/medik8s/machine-deletion-remediation.git"},
	"storage-based remediation":    {Name: "storage-based-remediation", RepoURL: "https://github.com/medik8s/storage-based-remediation.git"},
	"node remediation console":     {Name: "node-remediation-console", RepoURL: "https://github.com/medik8s/node-remediation-console.git"},
}

func DeriveOperatorName(component string) string {
	lower := strings.ToLower(component)
	for key, info := range operatorMap {
		if strings.Contains(lower, key) {
			return info.Name
		}
	}
	return strings.ToLower(strings.ReplaceAll(component, " ", "-"))
}

func DeriveRepoURL(component string) string {
	lower := strings.ToLower(component)
	for key, info := range operatorMap {
		if strings.Contains(lower, key) {
			return info.RepoURL
		}
	}
	return ""
}

func isExplicitlyGo(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "golang:") ||
		strings.Contains(lower, "golang ") ||
		goPackageInText(lower)
}

func goPackageInText(lower string) bool {
	return strings.Contains(lower, "golang.org/") ||
		strings.Contains(lower, "google.golang.org/") ||
		stdlibInText(lower)
}

func stdlibInText(lower string) bool {
	prefixes := []string{"crypto/", "net/", "encoding/", "archive/", "compress/",
		"html/", "text/", "math/", "os/", "path/", "go/parser", "database/", "image/"}
	for _, p := range prefixes {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func isGoRelatedCVE(ticket *jira.TicketInfo) bool {
	if isExplicitlyGo(ticket.Summary) {
		return true
	}
	return !isNonGoDescription(ticket.Summary)
}

var nonGoIndicators = []string{
	"python", " pip ", "setuptools", "python-requests", "urllib3",
	"ply ", "ruby", "perl ", "java ", "node.js", " npm ",
	"php ", "c library", "glibc", "libxml", "wheel:", "postgres",
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

func fixFunctionsInCallPaths(fixFunctions string, callPaths []string) bool {
	for _, entry := range strings.Split(fixFunctions, ", ") {
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			continue
		}
		funcName := parts[1]
		for _, path := range callPaths {
			if strings.Contains(path, funcName) {
				return true
			}
		}
	}
	return false
}

func cveDescription(info *cve.CVEInfo) string {
	if info == nil {
		return ""
	}
	return info.Description
}

func detectLanguage(isGoVuln bool, ticket *jira.TicketInfo, cveDesc string) string {
	if isGoVuln {
		return "Golang"
	}
	for _, text := range []string{ticket.Summary, cveDesc} {
		if lang := detectLanguageFromText(text); lang != "" {
			return lang
		}
	}
	return "Unknown"
}

var languagePatterns = []struct {
	lang       string
	indicators []string
}{
	{"Python", []string{"python", "urllib3", "setuptools", " pip ", "wheel:", "pypa/"}},
	{"JavaScript", []string{"node.js", " npm ", "javascript"}},
	{"Ruby", []string{"ruby"}},
	{"Java", []string{"java "}},
	{"Perl", []string{"perl "}},
	{"PHP", []string{"php "}},
	{"C", []string{"glibc", "c library", "libxml", "buffer overflow"}},
	{"SQL", []string{"postgres", "mysql", "mariadb", "sql injection"}},
	{"Golang", []string{"golang:", "golang ", "golang.org/"}},
}

func detectLanguageFromText(text string) string {
	if text == "" {
		return ""
	}
	lower := strings.ToLower(text)
	for _, p := range languagePatterns {
		for _, ind := range p.indicators {
			if strings.Contains(lower, ind) {
				return p.lang
			}
		}
	}
	return ""
}

func extractNonGoPackage(ticket *jira.TicketInfo, cveDesc string) string {
	for _, text := range []string{ticket.Summary, cveDesc} {
		lower := strings.ToLower(text)
		for _, pkg := range knownNonGoPackages {
			if strings.Contains(lower, pkg) {
				return pkg
			}
		}
	}
	if m := nonGoPkgRe.FindStringSubmatch(ticket.Summary); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return "unknown"
}

var knownNonGoPackages = []string{
	"urllib3", "requests", "setuptools", "pip", "wheel",
	"goproxy", "go-yaml", "protobuf", "grpc",
	"containerd", "runc", "etcd", "postgres", "mysql",
}

var nonGoPkgRe = regexp.MustCompile(`(?:container|operator-container):\s+(.+?):\s+`)

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

func firstSentence(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if i := strings.Index(s, ". "); i != -1 {
		return s[:i+1]
	}
	if strings.HasSuffix(s, ".") {
		return s
	}
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

func extractGoReviewLink(refs []string) string {
	for _, ref := range refs {
		if strings.Contains(ref, "go-review.googlesource.com") {
			return ref
		}
	}
	for _, ref := range refs {
		if strings.HasPrefix(ref, "https://go.dev/cl/") {
			clNum := strings.TrimPrefix(ref, "https://go.dev/cl/")
			return fmt.Sprintf("https://go-review.googlesource.com/c/go/+/%s", clNum)
		}
	}
	return ""
}

func extractVulnIDFromRefs(refs []string) string {
	for _, ref := range refs {
		if m := goVulnIDRe.FindString(ref); m != "" {
			return m
		}
	}
	return ""
}

func formatAffectedRanges(ranges []goversion.AffectedRange) string {
	if len(ranges) == 0 {
		return ""
	}
	var parts []string
	for _, r := range ranges {
		if r.Fixed != "" {
			if r.Introduced != "" && r.Introduced != "0" {
				parts = append(parts, fmt.Sprintf(">= %s, < %s", r.Introduced, r.Fixed))
			} else {
				parts = append(parts, fmt.Sprintf("< %s", r.Fixed))
			}
		} else if r.Introduced != "" {
			parts = append(parts, fmt.Sprintf(">= %s", r.Introduced))
		}
	}
	return strings.Join(parts, "; ")
}

func buildGoModLink(component, branch string, line int) string {
	repoURL := DeriveRepoURL(component)
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

func formatOperator(name, version, source string) string {
	if version == "" {
		return name
	}
	if source != "" && source != "title" {
		return fmt.Sprintf("%s:v%s [%s]", name, version, source)
	}
	return fmt.Sprintf("%s:v%s", name, version)
}

func generateRecommendation(r *types.Result) string {
	fixVersion := r.Vulnerability.FixVersion
	pkg := r.Vulnerability.Package

	switch r.Recommendation.Classification {
	case types.FixableNow:
		if fixVersion != "" {
			return fmt.Sprintf("Dependency or Go version bump to %s available. Create fix PR.", fixVersion)
		}
		return "Fix available. Create fix PR with dependency bump."
	case types.BlockedByGo:
		switch r.Recommendation.Priority {
		case types.PriorityCritical:
			return fmt.Sprintf("REACHABLE high-severity vuln on active support. Go %s required — may qualify for RHSA. Escalate to base image team.", fixVersion)
		case types.PriorityHigh:
			return fmt.Sprintf("Go version bump to %s required. Blocked by downstream base image — prioritize for next z-stream or operator release.", fixVersion)
		default:
			return fmt.Sprintf("Go version bump to %s required. Blocked by downstream base image — defer to next operator/RHWA release.", fixVersion)
		}
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
