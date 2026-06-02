package route

import (
	"testing"

	"github.com/razo7/vigil/pkg/types"
)

func TestDecideGoMinor(t *testing.T) {
	result := &types.Result{
		Vulnerability: types.VulnInfo{
			Package:    "crypto/tls",
			FixVersion: "",
		},
		Analysis: types.AnalysisInfo{
			ReleaseBranch: &types.BranchAnalysis{
				Upstream: types.UpstreamInfo{
					GoVersion: "1.22.5",
				},
			},
		},
		Recommendation: types.RecommendationInfo{
			Classification: types.FixableNow,
		},
	}
	got := Decide(result)
	if got != RouteGoMinor {
		t.Errorf("expected %s, got %s", RouteGoMinor, got)
	}
}

func TestDecideDependencyBump(t *testing.T) {
	result := &types.Result{
		Vulnerability: types.VulnInfo{
			Package:    "golang.org/x/net",
			FixVersion: "v0.33.0",
		},
		Recommendation: types.RecommendationInfo{
			Classification: types.FixableNow,
		},
	}
	got := Decide(result)
	if got != RouteDependencyBump {
		t.Errorf("expected %s, got %s", RouteDependencyBump, got)
	}
}

func TestDecideSemanticFix(t *testing.T) {
	result := &types.Result{
		Vulnerability: types.VulnInfo{
			Package:    "golang.org/x/net",
			FixVersion: "",
		},
		Recommendation: types.RecommendationInfo{
			Classification: types.FixableNow,
		},
	}
	got := Decide(result)
	if got != RouteSemanticFix {
		t.Errorf("expected %s, got %s", RouteSemanticFix, got)
	}
}

func TestDecideManualUnknown(t *testing.T) {
	result := &types.Result{
		Recommendation: types.RecommendationInfo{
			Classification: types.Unknown,
		},
	}
	got := Decide(result)
	if got != RouteManual {
		t.Errorf("expected %s, got %s", RouteManual, got)
	}
}

func TestDecideManualMisassigned(t *testing.T) {
	result := &types.Result{
		Recommendation: types.RecommendationInfo{
			Classification: types.Misassigned,
		},
	}
	got := Decide(result)
	if got != RouteManual {
		t.Errorf("expected %s, got %s", RouteManual, got)
	}
}

func TestDecideManualNotReachable(t *testing.T) {
	result := &types.Result{
		Recommendation: types.RecommendationInfo{
			Classification: types.NotReachable,
		},
	}
	got := Decide(result)
	if got != RouteManual {
		t.Errorf("expected %s, got %s", RouteManual, got)
	}
}

func TestDecideManualBlockedByGo(t *testing.T) {
	result := &types.Result{
		Recommendation: types.RecommendationInfo{
			Classification: types.BlockedByGo,
		},
	}
	got := Decide(result)
	if got != RouteManual {
		t.Errorf("expected %s, got %s", RouteManual, got)
	}
}

func TestRouteString(t *testing.T) {
	tests := []struct {
		route Route
		want  string
	}{
		{RouteDependencyBump, "dependency-bump"},
		{RouteGoMinor, "go-minor"},
		{RouteSemanticFix, "semantic-fix"},
		{RouteManual, "manual"},
	}
	for _, tt := range tests {
		if got := tt.route.String(); got != tt.want {
			t.Errorf("Route(%q).String() = %q, want %q", tt.route, got, tt.want)
		}
	}
}

func TestRouteEmoji(t *testing.T) {
	tests := []struct {
		route Route
		want  string
	}{
		{RouteDependencyBump, "\U0001F4E6"},
		{RouteGoMinor, "\U0001F527"},
		{RouteSemanticFix, "\U0001F916"},
		{RouteManual, "\U0001F464"},
		{Route("unknown"), "❓"},
	}
	for _, tt := range tests {
		if got := tt.route.Emoji(); got != tt.want {
			t.Errorf("Route(%q).Emoji() = %q, want %q", tt.route, got, tt.want)
		}
	}
}

func TestIsStdlib(t *testing.T) {
	tests := []struct {
		pkg  string
		want bool
	}{
		{"crypto/tls", true},
		{"net/http", true},
		{"golang.org/x/net", false},
		{"github.com/foo/bar", false},
	}
	for _, tt := range tests {
		if got := isStdlib(tt.pkg); got != tt.want {
			t.Errorf("isStdlib(%q) = %v, want %v", tt.pkg, got, tt.want)
		}
	}
}
