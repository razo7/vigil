package trivy

import (
	"testing"
)

func TestCvssScore(t *testing.T) {
	tests := []struct {
		name string
		vuln Vulnerability
		want float64
	}{
		{
			name: "nvd score",
			vuln: Vulnerability{
				CVSS: map[string]CVSSv3{"nvd": {V3Score: 7.5}},
			},
			want: 7.5,
		},
		{
			name: "redhat score preferred over unknown",
			vuln: Vulnerability{
				CVSS: map[string]CVSSv3{
					"redhat": {V3Score: 6.5},
					"other":  {V3Score: 8.0},
				},
			},
			want: 6.5,
		},
		{
			name: "fallback to severity label",
			vuln: Vulnerability{
				Severity: "HIGH",
			},
			want: 7.5,
		},
		{
			name: "critical severity fallback",
			vuln: Vulnerability{
				Severity: "CRITICAL",
			},
			want: 9.0,
		},
		{
			name: "no score",
			vuln: Vulnerability{},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cvssScore(tt.vuln)
			if got != tt.want {
				t.Errorf("cvssScore() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToDiscoveredVulns(t *testing.T) {
	report := &Report{
		Results: []Result{
			{
				Target: "go.mod",
				Class:  "lang-pkgs",
				Type:   "gomod",
				Vulnerabilities: []Vulnerability{
					{
						VulnerabilityID:  "CVE-2024-12345",
						PkgName:          "golang.org/x/net",
						InstalledVersion: "v0.10.0",
						FixedVersion:     "0.17.0",
						Severity:         "HIGH",
						Title:            "Test vulnerability",
						CVSS:             map[string]CVSSv3{"nvd": {V3Score: 7.5}},
					},
					{
						VulnerabilityID:  "CVE-2024-12345",
						PkgName:          "golang.org/x/net",
						InstalledVersion: "v0.10.0",
						FixedVersion:     "0.17.0",
						Severity:         "HIGH",
						Title:            "Duplicate",
					},
				},
			},
			{
				Target: "package-lock.json",
				Type:   "npm",
				Vulnerabilities: []Vulnerability{
					{
						VulnerabilityID: "CVE-2024-99999",
						PkgName:         "lodash",
						Severity:        "CRITICAL",
					},
				},
			},
		},
	}

	vulns := ToDiscoveredVulns(report, "1.25.0")

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln (deduplicated, gomod only), got %d", len(vulns))
	}

	v := vulns[0]
	if v.VulnID != "CVE-2024-12345" {
		t.Errorf("VulnID = %q, want CVE-2024-12345", v.VulnID)
	}
	if v.Package != "golang.org/x/net" {
		t.Errorf("Package = %q, want golang.org/x/net", v.Package)
	}
	if v.PackageSource != "trivy" {
		t.Errorf("PackageSource = %q, want trivy", v.PackageSource)
	}
	if v.Source != "Trivy" {
		t.Errorf("Source = %q, want Trivy", v.Source)
	}
	if v.Severity != 7.5 {
		t.Errorf("Severity = %v, want 7.5", v.Severity)
	}
	if v.Reachability != "MODULE-LEVEL" {
		t.Errorf("Reachability = %q, want MODULE-LEVEL", v.Reachability)
	}
}

func TestToDiscoveredVulnsEmpty(t *testing.T) {
	report := &Report{Results: []Result{}}
	vulns := ToDiscoveredVulns(report, "1.25.0")
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns for empty report, got %d", len(vulns))
	}
}
