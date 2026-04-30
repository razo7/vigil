package trivy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/razo7/vigil/pkg/classify"
	"github.com/razo7/vigil/pkg/types"
)

type Report struct {
	SchemaVersion int      `json:"SchemaVersion"`
	Results       []Result `json:"Results"`
}

type Result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string            `json:"VulnerabilityID"`
	PkgName          string            `json:"PkgName"`
	InstalledVersion string            `json:"InstalledVersion"`
	FixedVersion     string            `json:"FixedVersion"`
	Status           string            `json:"Status"`
	Title            string            `json:"Title"`
	Description      string            `json:"Description"`
	Severity         string            `json:"Severity"`
	PrimaryURL       string            `json:"PrimaryURL"`
	CVSS             map[string]CVSSv3 `json:"CVSS"`
}

type CVSSv3 struct {
	V3Score float64 `json:"V3Score"`
}

func Run(repoPath string) (*Report, error) {
	trivyPath, err := exec.LookPath("trivy")
	if err != nil {
		return nil, fmt.Errorf("trivy not found in PATH: %w", err)
	}

	cmd := exec.Command(trivyPath, "fs", "--format", "json", "--scanners", "vuln", "--quiet", repoPath)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running trivy: %w", err)
	}

	var report Report
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("parsing trivy output: %w", err)
	}
	return &report, nil
}

func ToDiscoveredVulns(report *Report, currentGo string) []types.DiscoveredVuln {
	seen := make(map[string]bool)
	var vulns []types.DiscoveredVuln

	for _, result := range report.Results {
		if result.Type != "gomod" {
			continue
		}
		for _, v := range result.Vulnerabilities {
			if seen[v.VulnerabilityID] {
				continue
			}
			seen[v.VulnerabilityID] = true

			severity := cvssScore(v)
			severityLabel := v.Severity

			isGoVuln := true
			reachability := "MODULE-LEVEL"

			input := classify.Input{
				IsGoVuln:    isGoVuln,
				FixGoVersion: v.FixedVersion,
				CurrentGo:   currentGo,
				CVSS:        severity,
			}
			classification, priority, _ := classify.Classify(input)

			dv := types.DiscoveredVuln{
				VulnID:         v.VulnerabilityID,
				Description:    v.Title,
				CVEIDs:         []string{v.VulnerabilityID},
				Package:        v.PkgName,
				PackageSource:  "trivy",
				Language:       "Go",
				LanguageSource: "trivy",
				Reachability:   reachability,
				FixVersion:     v.FixedVersion,
				Severity:       severity,
				SeverityLabel:  strings.ToTitle(strings.ToLower(severityLabel)),
				Classification: classification,
				Priority:       priority,
				Source:         "Trivy",
			}
			vulns = append(vulns, dv)
		}
	}
	return vulns
}

func cvssScore(v Vulnerability) float64 {
	for _, source := range []string{"nvd", "redhat", "ghsa"} {
		if c, ok := v.CVSS[source]; ok && c.V3Score > 0 {
			return c.V3Score
		}
	}
	for _, c := range v.CVSS {
		if c.V3Score > 0 {
			return c.V3Score
		}
	}
	switch strings.ToUpper(v.Severity) {
	case "CRITICAL":
		return 9.0
	case "HIGH":
		return 7.5
	case "MEDIUM":
		return 5.0
	case "LOW":
		return 2.5
	}
	return 0
}
