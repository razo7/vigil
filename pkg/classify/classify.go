package classify

import (
	"github.com/razo7/vigil/pkg/types"
)

// POC: hardcoded RHEL8→RHEL9 transition thresholds.
// Production should use live lookup from Jira or the support matrix.
var rhel8Thresholds = map[string]string{
	"self-node-remediation":        "0.10.0",
	"node-healthcheck-controller":  "0.9.0",
	"node-maintenance-operator":    "5.4.0",
	"machine-deletion-remediation": "0.4.0",
	"fence-agents-remediation":     "0.5.0",
}

type Input struct {
	IsGoVuln       bool
	IsReachable    bool
	IsPackageLevel bool
	FixGoVersion   string
	CurrentGo      string
	DownstreamGo   string
	ImageName      string
	OperatorName   string
	AffectsVersion string
	CVSS           float64
	SupportPhase   types.SupportPhase
}

func Classify(in Input) (types.Classification, types.Priority, string) {
	if reason := checkMisassignment(in); reason != "" {
		return types.Misassigned, types.PriorityMisassigned, reason
	}

	if !in.IsGoVuln {
		return types.NotGo, types.PriorityManual, ""
	}

	if !in.IsReachable && !in.IsPackageLevel {
		return types.NotReachable, types.PriorityLow, ""
	}

	if in.FixGoVersion != "" && in.DownstreamGo != "" {
		if CompareVersions(in.FixGoVersion, in.DownstreamGo) > 0 {
			return types.BlockedByGo, types.PriorityBlocked, ""
		}
	}

	return types.FixableNow, determinePriority(in.CVSS, in.SupportPhase), ""
}

func determinePriority(cvss float64, phase types.SupportPhase) types.Priority {
	isActive := phase == types.PhaseGA || phase == types.PhaseEUS1

	if cvss >= 7.0 && isActive {
		return types.PriorityCritical
	}
	if cvss >= 7.0 {
		return types.PriorityHigh
	}
	if isActive {
		return types.PriorityHigh
	}
	return types.PriorityMedium
}

func checkMisassignment(in Input) string {
	if isBundleImage(in.ImageName) {
		return "Go CVE assigned to bundle image (OLM metadata only, no Go runtime)"
	}

	if isRHEL8Image(in.ImageName) {
		threshold, ok := rhel8Thresholds[in.OperatorName]
		if ok && in.AffectsVersion != "" {
			if CompareVersions(in.AffectsVersion, threshold) < 0 {
				return "CVE targets RHEL8-based image for unsupported operator version (pre-RHEL9 transition)"
			}
		}
	}

	return ""
}

func isBundleImage(name string) bool {
	if name == "" {
		return false
	}
	for _, pattern := range []string{"bundle", "-metadata"} {
		if containsIgnoreCase(name, pattern) {
			return true
		}
	}
	return false
}

func isRHEL8Image(name string) bool {
	if name == "" {
		return false
	}
	return containsIgnoreCase(name, "rhel8") || containsIgnoreCase(name, "rhel-8")
}

func containsIgnoreCase(s, substr string) bool {
	ls := toLower(s)
	lsub := toLower(substr)
	for i := 0; i <= len(ls)-len(lsub); i++ {
		if ls[i:i+len(lsub)] == lsub {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
