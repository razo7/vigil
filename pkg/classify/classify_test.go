package classify

import (
	"testing"

	"github.com/razo7/vigil/pkg/types"
)

func TestClassify_FixableNow(t *testing.T) {
	in := Input{
		IsGoVuln:     true,
		IsReachable:  true,
		FixGoVersion: "1.25.5",
		CurrentGo:    "1.25.3",
		DownstreamGo: "1.25.6",
		CVSS:         7.5,
		SupportPhase: types.PhaseGA,
	}

	class, priority, reason := Classify(in)
	if class != types.FixableNow {
		t.Errorf("expected fixable-now, got %s", class)
	}
	if priority != types.PriorityCritical {
		t.Errorf("expected Critical, got %s", priority)
	}
	if reason != "" {
		t.Errorf("expected no reason, got %s", reason)
	}
}

func TestClassify_BlockedByGo(t *testing.T) {
	in := Input{
		IsGoVuln:     true,
		IsReachable:  true,
		FixGoVersion: "1.25.9",
		CurrentGo:    "1.25.3",
		DownstreamGo: "1.25.3",
	}

	class, priority, _ := Classify(in)
	if class != types.BlockedByGo {
		t.Errorf("expected blocked-by-go, got %s", class)
	}
	if priority != types.PriorityBlocked {
		t.Errorf("expected Blocked, got %s", priority)
	}
}

func TestClassify_NotReachable(t *testing.T) {
	in := Input{
		IsGoVuln:    true,
		IsReachable: false,
	}

	class, priority, _ := Classify(in)
	if class != types.NotReachable {
		t.Errorf("expected not-reachable, got %s", class)
	}
	if priority != types.PriorityLow {
		t.Errorf("expected Low, got %s", priority)
	}
}

func TestClassify_PackageLevel_FixableNow(t *testing.T) {
	in := Input{
		IsGoVuln:       true,
		IsReachable:    false,
		IsPackageLevel: true,
		FixGoVersion:   "1.25.5",
		CurrentGo:      "1.25.3",
		DownstreamGo:   "1.25.6",
		CVSS:           5.0,
		SupportPhase:   types.PhaseMaintenance,
	}

	class, priority, _ := Classify(in)
	if class != types.FixableNow {
		t.Errorf("expected fixable-now for package-level vuln with available fix, got %s", class)
	}
	if priority != types.PriorityMedium {
		t.Errorf("expected Medium (low CVSS + maintenance), got %s", priority)
	}
}

func TestClassify_NotGo(t *testing.T) {
	in := Input{
		IsGoVuln: false,
	}

	class, priority, _ := Classify(in)
	if class != types.NotGo {
		t.Errorf("expected not-go, got %s", class)
	}
	if priority != types.PriorityManual {
		t.Errorf("expected Needs manual review, got %s", priority)
	}
}

func TestClassify_MisassignedBundle(t *testing.T) {
	in := Input{
		IsGoVuln:  true,
		ImageName: "far-operator-bundle",
	}

	class, priority, reason := Classify(in)
	if class != types.Misassigned {
		t.Errorf("expected misassigned, got %s", class)
	}
	if priority != types.PriorityMisassigned {
		t.Errorf("expected Misassigned priority, got %s", priority)
	}
	if reason == "" {
		t.Error("expected misassignment reason")
	}
}

func TestClassify_MisassignedRHEL8(t *testing.T) {
	in := Input{
		IsGoVuln:       true,
		ImageName:      "far-rhel8-operator",
		OperatorName:   "fence-agents-remediation",
		AffectsVersion: "0.4.0",
	}

	class, _, reason := Classify(in)
	if class != types.Misassigned {
		t.Errorf("expected misassigned for RHEL8 image with old version, got %s", class)
	}
	if reason == "" {
		t.Error("expected misassignment reason for RHEL8")
	}
}

func TestClassify_RHEL8_CurrentVersion_NotMisassigned(t *testing.T) {
	in := Input{
		IsGoVuln:       true,
		IsReachable:    true,
		ImageName:      "far-rhel8-operator",
		OperatorName:   "fence-agents-remediation",
		AffectsVersion: "0.6.0",
		FixGoVersion:   "1.25.5",
		CurrentGo:      "1.25.3",
		DownstreamGo:   "1.25.6",
		SupportPhase:   types.PhaseGA,
		CVSS:           8.0,
	}

	class, _, _ := Classify(in)
	if class == types.Misassigned {
		t.Errorf("version 0.6.0 >= threshold 0.5.0 should NOT be misassigned, got %s", class)
	}
}

func TestDeterminePriority(t *testing.T) {
	tests := []struct {
		name     string
		cvss     float64
		phase    types.SupportPhase
		expected types.Priority
	}{
		{"high CVSS + GA", 9.0, types.PhaseGA, types.PriorityCritical},
		{"high CVSS + EUS1", 7.5, types.PhaseEUS1, types.PriorityCritical},
		{"high CVSS + Maintenance", 8.0, types.PhaseMaintenance, types.PriorityHigh},
		{"high CVSS + EUS3", 7.0, types.PhaseEUS3, types.PriorityHigh},
		{"low CVSS + GA", 5.0, types.PhaseGA, types.PriorityHigh},
		{"low CVSS + EUS1", 4.0, types.PhaseEUS1, types.PriorityHigh},
		{"low CVSS + Maintenance", 3.0, types.PhaseMaintenance, types.PriorityMedium},
		{"low CVSS + EUS2", 6.9, types.PhaseEUS2, types.PriorityMedium},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determinePriority(tt.cvss, tt.phase)
			if got != tt.expected {
				t.Errorf("determinePriority(%.1f, %s) = %s, want %s", tt.cvss, tt.phase, got, tt.expected)
			}
		})
	}
}
