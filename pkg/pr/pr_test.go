package pr

import (
	"strings"
	"testing"
)

func TestFormatDescription(t *testing.T) {
	opts := Options{
		CVEID:      "CVE-2026-32283",
		Package:    "golang.org/x/net",
		FixVersion: "v0.33.0",
		Strategy:   "direct",
		Risk:       1,
		TicketID:   "RHWA-881",
	}

	desc := FormatDescription(opts)

	checks := []string{
		"CVE-2026-32283",
		"golang.org/x/net",
		"v0.33.0",
		"direct",
		"risk 1",
		"RHWA-881",
		"## Summary",
		"## Test plan",
	}

	for _, check := range checks {
		if !strings.Contains(desc, check) {
			t.Errorf("description missing %q", check)
		}
	}

	if strings.Contains(desc, "Generated with Claude Code") {
		t.Error("description should not contain Claude attribution")
	}
}

func TestFormatDescriptionWithValidation(t *testing.T) {
	opts := Options{
		CVEID:      "CVE-2026-32283",
		Package:    "golang.org/x/net",
		FixVersion: "v0.33.0",
		Strategy:   "direct",
		Risk:       1,
	}

	steps := []ValidationStep{
		{Name: "go mod tidy", Passed: true},
		{Name: "govulncheck", Passed: true},
		{Name: "go build", Passed: true},
	}

	desc := FormatDescriptionWithValidation(opts, steps)

	if !strings.Contains(desc, "Validation results") {
		t.Error("expected validation results section")
	}
	if !strings.Contains(desc, "[PASS] go mod tidy") {
		t.Error("expected PASS for go mod tidy")
	}
}
