package discover

import (
	"testing"

	"github.com/razo7/vigil/pkg/jira"
	"github.com/razo7/vigil/pkg/types"
)

func TestFindMatchingTickets(t *testing.T) {
	tickets := map[string]*jira.TicketInfo{
		"CVE-2026-32283": {Key: "RHWA-881", Status: "New", CVEID: "CVE-2026-32283"},
		"CVE-2025-25679": {Key: "RHWA-805", Status: "New", CVEID: "CVE-2025-25679"},
	}

	tests := []struct {
		name      string
		aliases   []string
		wantCount int
		wantFirst string
	}{
		{
			name:      "single match",
			aliases:   []string{"CVE-2026-32283"},
			wantCount: 1,
			wantFirst: "RHWA-881",
		},
		{
			name:      "no match",
			aliases:   []string{"CVE-9999-00001"},
			wantCount: 0,
		},
		{
			name:      "multiple aliases one match",
			aliases:   []string{"CVE-9999-00001", "CVE-2025-25679"},
			wantCount: 1,
			wantFirst: "RHWA-805",
		},
		{
			name:      "nil ticket map",
			aliases:   []string{"CVE-2026-32283"},
			wantCount: 0,
		},
		{
			name:      "empty aliases",
			aliases:   nil,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ticketMap := tickets
			if tt.name == "nil ticket map" {
				ticketMap = nil
			}

			matched := findMatchingTickets(tt.aliases, ticketMap)
			if len(matched) != tt.wantCount {
				t.Errorf("got %d matches, want %d", len(matched), tt.wantCount)
			}
			if tt.wantFirst != "" && len(matched) > 0 && matched[0].Key != tt.wantFirst {
				t.Errorf("first match = %s, want %s", matched[0].Key, tt.wantFirst)
			}
		})
	}
}

func TestSortVulns(t *testing.T) {
	vulns := []types.DiscoveredVuln{
		{VulnID: "low-module", Priority: types.PriorityLow, Reachability: "MODULE-LEVEL", Severity: 4.0},
		{VulnID: "crit-reach", Priority: types.PriorityCritical, Reachability: "REACHABLE", Severity: 9.0},
		{VulnID: "high-pkg", Priority: types.PriorityHigh, Reachability: "PACKAGE-LEVEL", Severity: 7.5},
		{VulnID: "crit-test", Priority: types.PriorityCritical, Reachability: "TEST-ONLY", Severity: 8.0},
	}

	sortVulns(vulns)

	expected := []string{"crit-reach", "crit-test", "high-pkg", "low-module"}
	for i, want := range expected {
		if vulns[i].VulnID != want {
			t.Errorf("position %d: got %s, want %s", i, vulns[i].VulnID, want)
		}
	}
}

func TestMatchedCVEIDs(t *testing.T) {
	result := &types.DiscoverResult{
		Vulns: []types.DiscoveredVuln{
			{CVEIDs: []string{"CVE-2026-1111", "CVE-2026-2222"}, Source: "Both"},
			{CVEIDs: []string{"CVE-2026-3333"}, Source: "Scan"},
		},
	}

	m := MatchedCVEIDs(result)

	if m["CVE-2026-1111"] != "Both" {
		t.Errorf("CVE-2026-1111 source = %q, want Both", m["CVE-2026-1111"])
	}
	if m["CVE-2026-2222"] != "Both" {
		t.Errorf("CVE-2026-2222 source = %q, want Both", m["CVE-2026-2222"])
	}
	if m["CVE-2026-3333"] != "Scan" {
		t.Errorf("CVE-2026-3333 source = %q, want Scan", m["CVE-2026-3333"])
	}
	if _, ok := m["CVE-9999-0000"]; ok {
		t.Error("unexpected match for CVE-9999-0000")
	}
}
