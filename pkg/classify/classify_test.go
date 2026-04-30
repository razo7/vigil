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

func TestClassify_BlockedByGo_HighSeverity(t *testing.T) {
	in := Input{
		IsGoVuln:     true,
		IsReachable:  true,
		FixGoVersion: "1.25.9",
		CurrentGo:    "1.25.3",
		DownstreamGo: "1.25.3",
		CVSS:         8.0,
		SupportPhase: types.PhaseGA,
	}

	class, priority, _ := Classify(in)
	if class != types.BlockedByGo {
		t.Errorf("expected blocked-by-go, got %s", class)
	}
	if priority != types.PriorityCritical {
		t.Errorf("expected Critical (reachable + high CVSS + GA), got %s", priority)
	}
}

func TestClassify_BlockedByGo_LowPriority(t *testing.T) {
	in := Input{
		IsGoVuln:       true,
		IsReachable:    false,
		IsPackageLevel: true,
		FixGoVersion:   "1.25.9",
		CurrentGo:      "1.20.0",
		DownstreamGo:   "1.20.0",
		CVSS:           5.0,
		SupportPhase:   types.PhaseMaintenance,
	}

	class, priority, _ := Classify(in)
	if class != types.BlockedByGo {
		t.Errorf("expected blocked-by-go, got %s", class)
	}
	if priority != types.PriorityLow {
		t.Errorf("expected Low (not reachable + low CVSS + maintenance), got %s", priority)
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

func TestClassify_Misassigned_EOL(t *testing.T) {
	in := Input{
		IsGoVuln:       true,
		ImageName:      "far-rhel8-operator",
		OperatorName:   "fence-agents-remediation",
		AffectsVersion: "0.4.0",
		SupportPhase:   types.PhaseEOL,
	}

	class, _, reason := Classify(in)
	if class != types.Misassigned {
		t.Errorf("expected misassigned for EOL operator version, got %s", class)
	}
	if reason == "" {
		t.Error("expected misassignment reason for EOL")
	}
}

func TestClassify_RHEL9_EOL_Misassigned(t *testing.T) {
	in := Input{
		IsGoVuln:       true,
		ImageName:      "far-rhel9-operator",
		OperatorName:   "fence-agents-remediation",
		AffectsVersion: "0.6.0",
		SupportPhase:   types.PhaseEOL,
	}

	class, _, reason := Classify(in)
	if class != types.Misassigned {
		t.Errorf("expected misassigned for RHEL9 EOL operator version, got %s", class)
	}
	if reason == "" {
		t.Error("expected misassignment reason for EOL")
	}
}

func TestClassify_RHEL8_NotEOL_NotMisassigned(t *testing.T) {
	in := Input{
		IsGoVuln:       true,
		ImageName:      "far-rhel8-operator",
		OperatorName:   "fence-agents-remediation",
		AffectsVersion: "0.4.0",
		SupportPhase:   types.PhaseEUS1,
	}

	class, _, _ := Classify(in)
	if class == types.Misassigned {
		t.Errorf("RHEL8 image with EUS1 support should NOT be misassigned, got %s", class)
	}
}

func TestClassify_RHEL8_GA_NotMisassigned(t *testing.T) {
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
		t.Errorf("RHEL8 image with GA support should NOT be misassigned, got %s", class)
	}
}

func TestClassify_ModuleBlockedByGo(t *testing.T) {
	// Simulates: golang.org/x/net@v0.40.0 requires go 1.23.0,
	// but downstream only has go 1.22.4.
	// FixGoVersion is set to "1.23.0" (the dependency's Go requirement,
	// resolved via module proxy) not "0.40.0" (the module version).
	in := Input{
		IsGoVuln:       true,
		IsReachable:    true,
		FixGoVersion:   "1.23.0",
		CurrentGo:      "1.22.0",
		DownstreamGo:   "1.22.4",
		CVSS:           6.5,
		SupportPhase:   types.PhaseGA,
	}

	class, _, _ := Classify(in)
	if class != types.BlockedByGo {
		t.Errorf("expected blocked-by-go when dependency requires Go 1.23.0 but downstream has 1.22.4, got %s", class)
	}
}

func TestClassify_ModuleFixable(t *testing.T) {
	// Simulates: dependency fix requires go 1.22.0,
	// downstream has go 1.25.8 — fix is feasible.
	in := Input{
		IsGoVuln:       true,
		IsReachable:    true,
		FixGoVersion:   "1.22.0",
		CurrentGo:      "1.25.0",
		DownstreamGo:   "1.25.8",
		CVSS:           6.5,
		SupportPhase:   types.PhaseGA,
	}

	class, _, _ := Classify(in)
	if class != types.FixableNow {
		t.Errorf("expected fixable-now when dependency requires Go 1.22.0 and downstream has 1.25.8, got %s", class)
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
