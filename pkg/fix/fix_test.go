package fix

import (
	"testing"

	"github.com/razo7/vigil/pkg/types"
)

func TestBuildStrategies_Auto_Stdlib(t *testing.T) {
	opts := Options{Strategy: StrategyAuto}
	strategies := buildStrategies(opts, "stdlib")

	if len(strategies) != 4 {
		t.Fatalf("expected 4 strategies for auto+stdlib, got %d", len(strategies))
	}
	if strategies[0].Name() != StrategyGoMinor {
		t.Errorf("first strategy should be gominor, got %s", strategies[0].Name())
	}
	if strategies[1].Name() != StrategyDirect {
		t.Errorf("second strategy should be direct, got %s", strategies[1].Name())
	}
}

func TestBuildStrategies_Auto_NonStdlib(t *testing.T) {
	opts := Options{Strategy: StrategyAuto}
	strategies := buildStrategies(opts, "golang.org/x/net")

	if len(strategies) != 3 {
		t.Fatalf("expected 3 strategies for auto+non-stdlib, got %d", len(strategies))
	}
	if strategies[0].Name() != StrategyDirect {
		t.Errorf("first strategy should be direct for non-stdlib, got %s", strategies[0].Name())
	}
}

func TestBuildStrategies_Auto_WithMajor(t *testing.T) {
	opts := Options{Strategy: StrategyAuto, ApproveMajor: true}
	strategies := buildStrategies(opts, "golang.org/x/net")

	if len(strategies) != 4 {
		t.Fatalf("expected 4 strategies with approve-major, got %d", len(strategies))
	}
	if strategies[3].Name() != StrategyMajor {
		t.Errorf("last strategy should be major, got %s", strategies[3].Name())
	}
}

func TestBuildStrategies_Specific(t *testing.T) {
	opts := Options{Strategy: StrategyDirect}
	strategies := buildStrategies(opts, "golang.org/x/net")

	if len(strategies) != 1 {
		t.Fatalf("expected 1 strategy for specific, got %d", len(strategies))
	}
	if strategies[0].Name() != StrategyDirect {
		t.Errorf("expected direct, got %s", strategies[0].Name())
	}
}

func TestBuildStrategies_MajorWithoutApproval(t *testing.T) {
	opts := Options{Strategy: StrategyMajor, ApproveMajor: false}
	strategies := buildStrategies(opts, "golang.org/x/net")

	if len(strategies) != 1 {
		t.Fatalf("expected 1 strategy, got %d", len(strategies))
	}
	// Strategy is built, but Apply will error without approval
}

func TestExtractRaw(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CVE-2026-32283 (https://www.cve.org/CVERecord?id=CVE-2026-32283)", "CVE-2026-32283"},
		{"RHWA-881 (https://redhat.atlassian.net/browse/RHWA-881)", "RHWA-881"},
		{"golang.org/x/net", "golang.org/x/net"},
		{"0.33.0", "0.33.0"},
		{"", ""},
	}

	for _, tt := range tests {
		if got := extractRaw(tt.input); got != tt.expected {
			t.Errorf("extractRaw(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestExtractModule(t *testing.T) {
	tests := []struct {
		name     string
		pkg      string
		expected string
	}{
		{"stdlib package", "crypto/tls", "stdlib"},
		{"third party", "golang.org/x/net", "golang.org/x/net"},
		{"stdlib with annotation", "crypto/tls (https://...)", "stdlib"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &types.Result{
				Vulnerability: types.VulnInfo{Package: tt.pkg},
			}
			got := extractModule(result)
			if got != tt.expected {
				t.Errorf("extractModule() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExtractOperatorName(t *testing.T) {
	result := &types.Result{
		Source: types.SourceInfo{
			AffectedOperatorVersion: "fence-agents-remediation 0.8 (from affects-version)",
		},
	}
	if got := extractOperatorName(result); got != "fence-agents-remediation" {
		t.Errorf("expected fence-agents-remediation, got %s", got)
	}
}
