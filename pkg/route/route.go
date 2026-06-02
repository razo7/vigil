package route

import (
	"strings"

	"github.com/razo7/vigil/pkg/types"
)

type Route string

const (
	RouteDependencyBump Route = "dependency-bump"
	RouteGoMinor        Route = "go-minor"
	RouteSemanticFix    Route = "semantic-fix"
	RouteManual         Route = "manual"
)

func Decide(result *types.Result) Route {
	class := result.Recommendation.Classification

	if class == types.Unknown || class == types.Misassigned {
		return RouteManual
	}
	if class == types.NotReachable {
		return RouteManual
	}
	if class != types.FixableNow {
		return RouteManual
	}

	pkg := result.Vulnerability.Package
	if isStdlib(pkg) && result.Analysis.ReleaseBranch != nil {
		goVer := result.Analysis.ReleaseBranch.Upstream.GoVersion
		if goVer != "" {
			return RouteGoMinor
		}
	}

	if result.Vulnerability.FixVersion != "" {
		return RouteDependencyBump
	}

	return RouteSemanticFix
}

func isStdlib(pkg string) bool {
	return !strings.Contains(pkg, ".")
}

func (r Route) String() string { return string(r) }

func (r Route) Emoji() string {
	switch r {
	case RouteDependencyBump:
		return "\U0001F4E6"
	case RouteGoMinor:
		return "\U0001F527"
	case RouteSemanticFix:
		return "\U0001F916"
	case RouteManual:
		return "\U0001F464"
	default:
		return "❓"
	}
}
