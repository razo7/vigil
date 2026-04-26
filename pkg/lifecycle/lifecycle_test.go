package lifecycle

import (
	"testing"
	"time"

	"github.com/razo7/vigil/pkg/types"
)

func TestLookupOCPVersion(t *testing.T) {
	tests := []struct {
		operator string
		version  string
		expected string
	}{
		{"fence-agents-remediation", "0.4", "4.16"},
		{"fence-agents-remediation", "0.6", "4.20"},
		{"fence-agents-remediation", "0.7", "4.21"},
		{"self-node-remediation", "0.11", "4.20"},
		{"node-maintenance-operator", "5.4", "4.19"},
		{"machine-deletion-remediation", "0.5", "4.20"},
		{"fence-agents-remediation", "99.99", ""},
		{"unknown-operator", "0.1", ""},
	}

	for _, tc := range tests {
		t.Run(tc.operator+"/"+tc.version, func(t *testing.T) {
			got := LookupOCPVersion(tc.operator, tc.version)
			if got != tc.expected {
				t.Errorf("LookupOCPVersion(%s, %s) = %s, want %s", tc.operator, tc.version, got, tc.expected)
			}
		})
	}
}

func TestLookupOCPVersion_NormalizePrefix(t *testing.T) {
	got := LookupOCPVersion("fence-agents-remediation", "v0.6")
	if got != "4.20" {
		t.Errorf("expected 4.20 for v0.6, got %s", got)
	}
}

func TestLookupSupportPhaseAt(t *testing.T) {
	tests := []struct {
		name     string
		ocp      string
		at       time.Time
		expected types.SupportPhase
	}{
		{"4.17 GA", "4.17", date(2025, 1, 1), types.PhaseGA},
		{"4.17 Maintenance", "4.17", date(2025, 8, 1), types.PhaseMaintenance},
		{"4.17 EOL", "4.17", date(2026, 5, 1), types.PhaseEOL},
		{"4.16 GA", "4.16", date(2024, 8, 1), types.PhaseGA},
		{"4.16 EUS1", "4.16", date(2025, 3, 1), types.PhaseEUS1},
		{"4.16 EUS2", "4.16", date(2026, 2, 1), types.PhaseEUS2},
		{"4.18 GA", "4.18", date(2025, 5, 1), types.PhaseGA},
		{"4.21 GA", "4.21", date(2026, 4, 26), types.PhaseGA},
		{"unknown version", "4.99", date(2026, 1, 1), types.PhaseUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := LookupSupportPhaseAt(tc.ocp, tc.at)
			if got != tc.expected {
				t.Errorf("LookupSupportPhaseAt(%s, %v) = %s, want %s", tc.ocp, tc.at, got, tc.expected)
			}
		})
	}
}

func TestAllOCPVersionsForOperator(t *testing.T) {
	versions := AllOCPVersionsForOperator("fence-agents-remediation", "0.6")
	if len(versions) != 5 {
		t.Errorf("expected 5 OCP versions for FAR 0.6, got %d", len(versions))
	}
	if versions[0] != "4.16" {
		t.Errorf("expected first OCP version 4.16, got %s", versions[0])
	}
}
