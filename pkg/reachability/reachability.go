package reachability

import (
	"fmt"
	"os"
	"strings"

	"github.com/razo7/vigil/pkg/cve"
	"github.com/razo7/vigil/pkg/goversion"
	"github.com/razo7/vigil/pkg/lifecycle"
	"github.com/razo7/vigil/pkg/types"
)

type BranchResult struct {
	Branch       string
	GoVersion    string
	OCPVersion   string
	SupportPhase types.SupportPhase
	Vulns        []VulnResult
}

type VulnResult struct {
	CVEID         string
	Package       string
	Reachability  string
	EntryPoint    string
	FixFuncMatch  bool
	NeedsBackport bool
	CVSS          float64
	CallPaths     []string
}

func Analyze(repoPath, branch, goVersion, operatorName, operatorVersion string) (*BranchResult, error) {
	if !goversion.HasBranch(repoPath, branch) {
		return nil, fmt.Errorf("branch %s not found in repo", branch)
	}

	wtPath, cleanup, err := goversion.CreateWorktree(repoPath, branch)
	if err != nil {
		return nil, fmt.Errorf("creating worktree for %s: %w", branch, err)
	}
	defer cleanup()

	goMod, err := goversion.ReadGoMod(wtPath)
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	effectiveGo := goMod.EffectiveVersion()
	if goVersion != "" {
		effectiveGo = goVersion
	}

	fmt.Fprintf(os.Stderr, "Running govulncheck on %s (Go %s)...\n", branch, effectiveGo)
	vulnResult, err := goversion.RunGovulncheckWithVersion(wtPath, effectiveGo)
	if err != nil {
		return nil, fmt.Errorf("running govulncheck: %w", err)
	}

	ocpVersion := lifecycle.LookupOCPVersion(operatorName, operatorVersion)
	supportPhase := lifecycle.LookupSupportPhase(ocpVersion)

	var vulns []VulnResult
	for _, entry := range vulnResult.Vulns {
		reachLabel := goversion.ReachabilityLabel(&entry)

		entryPoint := extractEntryPoint(entry.CallPaths)

		var cvssScore float64
		if len(entry.Aliases) > 0 {
			if info, err := cve.FetchCVSSScore(entry.Aliases[0]); err == nil && info != nil {
				cvssScore = info.Score
			}
		}

		needsBackport := computeNeedsBackport(reachLabel, supportPhase)

		cveID := primaryCVEID(entry)

		vulns = append(vulns, VulnResult{
			CVEID:         cveID,
			Package:       entry.Package,
			Reachability:  reachLabel,
			EntryPoint:    entryPoint,
			FixFuncMatch:  false,
			NeedsBackport: needsBackport,
			CVSS:          cvssScore,
			CallPaths:     entry.CallPaths,
		})
	}

	return &BranchResult{
		Branch:       branch,
		GoVersion:    effectiveGo,
		OCPVersion:   ocpVersion,
		SupportPhase: supportPhase,
		Vulns:        vulns,
	}, nil
}

func computeNeedsBackport(reachLabel string, phase types.SupportPhase) bool {
	if phase == types.PhaseEOL {
		return false
	}
	return reachLabel == "REACHABLE" || reachLabel == "PACKAGE-LEVEL"
}

func primaryCVEID(entry goversion.VulnEntry) string {
	for _, alias := range entry.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	return entry.ID
}

func extractEntryPoint(callPaths []string) string {
	if len(callPaths) == 0 {
		return ""
	}
	parts := strings.Split(callPaths[0], " \xe2\x86\x92 ")
	for i := len(parts) - 1; i >= 0; i-- {
		start := strings.LastIndex(parts[i], "(")
		end := strings.LastIndex(parts[i], ")")
		if start < 0 || end <= start {
			continue
		}
		filename := parts[i][start+1 : end]
		if isInternalPath(filename) {
			continue
		}
		return filename
	}
	return ""
}

func isInternalPath(path string) bool {
	return strings.HasPrefix(path, "net/") ||
		strings.HasPrefix(path, "crypto/") ||
		strings.HasPrefix(path, "internal/") ||
		strings.HasPrefix(path, "encoding/") ||
		strings.HasPrefix(path, "archive/") ||
		strings.HasPrefix(path, "go/") ||
		strings.HasPrefix(path, "golang.org/") ||
		strings.Contains(path, "/vendor/")
}
