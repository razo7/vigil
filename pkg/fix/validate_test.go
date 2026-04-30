package fix

import (
	"testing"

	"github.com/razo7/vigil/pkg/goversion"
)

func TestCveStillPresent_ByAlias(t *testing.T) {
	result := &goversion.VulncheckResult{
		Vulns: []goversion.VulnEntry{
			{ID: "GO-2026-4870", Aliases: []string{"CVE-2026-32283"}},
		},
	}
	if !cveStillPresent(result, "CVE-2026-32283") {
		t.Error("expected CVE-2026-32283 to be present")
	}
}

func TestCveStillPresent_ByID(t *testing.T) {
	result := &goversion.VulncheckResult{
		Vulns: []goversion.VulnEntry{
			{ID: "GO-2026-4870"},
		},
	}
	if !cveStillPresent(result, "GO-2026-4870") {
		t.Error("expected GO-2026-4870 to be present")
	}
}

func TestCveStillPresent_Gone(t *testing.T) {
	result := &goversion.VulncheckResult{
		Vulns: []goversion.VulnEntry{
			{ID: "GO-2025-3488", Aliases: []string{"CVE-2025-22868"}},
		},
	}
	if cveStillPresent(result, "CVE-2026-32283") {
		t.Error("expected CVE-2026-32283 to be absent")
	}
}

func TestCveStillPresent_NilResult(t *testing.T) {
	if cveStillPresent(nil, "CVE-2026-32283") {
		t.Error("expected nil result to mean CVE absent")
	}
}

func TestAllStepsPassed(t *testing.T) {
	steps := []StepResult{
		{Name: "tidy", Passed: true},
		{Name: "build", Passed: true},
	}
	if !allStepsPassed(steps) {
		t.Error("expected all passed")
	}

	steps = append(steps, StepResult{Name: "test", Passed: false})
	if allStepsPassed(steps) {
		t.Error("expected not all passed")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 100) != "short" {
		t.Error("should not truncate short string")
	}
	long := "abcdefghij"
	if got := truncate(long, 5); got != "abcde..." {
		t.Errorf("expected 'abcde...', got %q", got)
	}
}
