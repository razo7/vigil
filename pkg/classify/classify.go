package classify

import (
	"github.com/razo7/vigil/pkg/types"
)

type Input struct {
	IsGoVuln            bool
	IsReachable         bool
	IsPackageLevel      bool
	FixFunctionMismatch bool
	TestOnly            bool
	FixGoVersion        string
	CurrentGo           string
	DownstreamGo        string
	ImageName           string
	OperatorName        string
	AffectsVersion      string
	CVSS                float64
	SupportPhase        types.SupportPhase
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
			return types.BlockedByGo, blockedPriority(in.IsReachable, in.CVSS, in.SupportPhase), ""
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

func blockedPriority(reachable bool, cvss float64, phase types.SupportPhase) types.Priority {
	isActive := phase == types.PhaseGA || phase == types.PhaseEUS1

	if reachable && cvss >= 7.0 && isActive {
		return types.PriorityCritical
	}
	if reachable && cvss >= 7.0 {
		return types.PriorityHigh
	}
	if reachable && isActive {
		return types.PriorityHigh
	}
	return types.PriorityLow
}

func checkMisassignment(in Input) string {
	if isBundleImage(in.ImageName) {
		return "Go CVE assigned to bundle image (OLM metadata only, no Go runtime)"
	}

	if in.SupportPhase == types.PhaseEOL {
		return "CVE targets EOL operator version (OCP support ended)"
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
