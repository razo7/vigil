package lifecycle

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/razo7/vigil/pkg/config"
	"github.com/razo7/vigil/pkg/types"
)

type OCPRelease struct {
	Version        string
	GA             time.Time
	EndFullSupport time.Time
	EndMaintenance time.Time
	EUS            bool
	EndEUS1        time.Time
	EndEUS2        time.Time
}

type OperatorOCPMapping struct {
	OperatorVersion string
	OCPVersions     []string
}

// Dates from https://access.redhat.com/support/policy/updates/openshift_operators#platform-aligned
var ocpReleases = []OCPRelease{
	{Version: "4.12", GA: date(2023, 1, 17), EndFullSupport: date(2023, 7, 17), EndMaintenance: date(2024, 7, 17), EUS: true, EndEUS1: date(2025, 1, 17)},
	{Version: "4.13", GA: date(2023, 5, 17), EndFullSupport: date(2023, 11, 17), EndMaintenance: date(2024, 11, 17)},
	{Version: "4.14", GA: date(2023, 10, 31), EndFullSupport: date(2024, 2, 20), EndMaintenance: date(2025, 5, 1), EUS: true, EndEUS1: date(2025, 10, 31), EndEUS2: date(2026, 10, 31)},
	{Version: "4.15", GA: date(2024, 2, 27), EndFullSupport: date(2024, 10, 16), EndMaintenance: date(2025, 8, 27)},
	{Version: "4.16", GA: date(2024, 6, 27), EndFullSupport: date(2025, 1, 21), EndMaintenance: date(2025, 12, 27), EUS: true, EndEUS1: date(2026, 6, 27), EndEUS2: date(2027, 6, 27)},
	{Version: "4.17", GA: date(2024, 10, 10), EndFullSupport: date(2025, 5, 25), EndMaintenance: date(2026, 4, 1)},
	{Version: "4.18", GA: date(2025, 3, 11), EndFullSupport: date(2025, 9, 16), EndMaintenance: date(2026, 8, 25), EUS: true, EndEUS1: date(2027, 2, 25), EndEUS2: date(2028, 2, 25)},
	{Version: "4.19", GA: date(2025, 6, 25), EndFullSupport: date(2026, 5, 3), EndMaintenance: date(2026, 12, 17)},
	{Version: "4.20", GA: date(2025, 11, 5), EndFullSupport: date(2026, 5, 3), EndMaintenance: date(2027, 4, 21), EUS: true, EndEUS1: date(2027, 10, 21), EndEUS2: date(2028, 10, 21)},
	{Version: "4.21", GA: date(2026, 3, 25), EndFullSupport: date(2026, 10, 25), EndMaintenance: date(2027, 9, 25)},
	{Version: "4.22", GA: date(2026, 6, 9), EndFullSupport: date(2027, 1, 9), EndMaintenance: date(2027, 12, 9), EUS: true, EndEUS1: date(2028, 6, 9), EndEUS2: date(2029, 6, 9)},
}

var operatorMappings = map[string][]OperatorOCPMapping{
	// Source: https://access.redhat.com/support/policy/updates/openshift_operators
	// Platform Aligned versions use the last OCP version in the list.
	// Rolling Stream versions cover multiple OCP versions.
	"fence-agents-remediation": {
		{OperatorVersion: "0.2", OCPVersions: []string{"4.14"}},
		{OperatorVersion: "0.4", OCPVersions: []string{"4.16"}},
		{OperatorVersion: "0.5", OCPVersions: []string{"4.18"}},
		{OperatorVersion: "0.6", OCPVersions: []string{"4.16", "4.17", "4.18", "4.19", "4.20"}},
		{OperatorVersion: "0.7", OCPVersions: []string{"4.21"}},
		{OperatorVersion: "0.8", OCPVersions: []string{"4.22"}},
	},
	"self-node-remediation": {
		{OperatorVersion: "0.5", OCPVersions: []string{"4.12"}},
		{OperatorVersion: "0.7", OCPVersions: []string{"4.14"}},
		{OperatorVersion: "0.9", OCPVersions: []string{"4.16"}},
		{OperatorVersion: "0.10", OCPVersions: []string{"4.14", "4.15", "4.16", "4.17", "4.18", "4.19"}},
		{OperatorVersion: "0.11", OCPVersions: []string{"4.16", "4.17", "4.18", "4.19", "4.20"}},
		{OperatorVersion: "0.12", OCPVersions: []string{"4.21"}},
		{OperatorVersion: "0.13", OCPVersions: []string{"4.22"}},
	},
	"node-healthcheck-operator": {
		{OperatorVersion: "0.4", OCPVersions: []string{"4.12"}},
		{OperatorVersion: "0.6", OCPVersions: []string{"4.14"}},
		{OperatorVersion: "0.8", OCPVersions: []string{"4.16"}},
		{OperatorVersion: "0.9", OCPVersions: []string{"4.18"}},
		{OperatorVersion: "0.10", OCPVersions: []string{"4.16", "4.17", "4.18", "4.19", "4.20"}},
		{OperatorVersion: "0.11", OCPVersions: []string{"4.21"}},
		{OperatorVersion: "0.12", OCPVersions: []string{"4.22"}},
	},
	"node-maintenance-operator": {
		{OperatorVersion: "5.0", OCPVersions: []string{"4.12"}},
		{OperatorVersion: "5.2", OCPVersions: []string{"4.14"}},
		{OperatorVersion: "5.3", OCPVersions: []string{"4.16"}},
		{OperatorVersion: "5.4", OCPVersions: []string{"4.14", "4.15", "4.16", "4.17", "4.18", "4.19"}},
		{OperatorVersion: "5.5", OCPVersions: []string{"4.16", "4.17", "4.18", "4.19", "4.20"}},
		{OperatorVersion: "5.6", OCPVersions: []string{"4.21"}},
		{OperatorVersion: "5.7", OCPVersions: []string{"4.22"}},
	},
	"machine-deletion-remediation": {
		{OperatorVersion: "0.2", OCPVersions: []string{"4.14"}},
		{OperatorVersion: "0.3", OCPVersions: []string{"4.16"}},
		{OperatorVersion: "0.4", OCPVersions: []string{"4.14", "4.15", "4.16", "4.17", "4.18", "4.19"}},
		{OperatorVersion: "0.5", OCPVersions: []string{"4.16", "4.17", "4.18", "4.19", "4.20"}},
		{OperatorVersion: "0.6", OCPVersions: []string{"4.21"}},
		{OperatorVersion: "0.7", OCPVersions: []string{"4.22"}},
	},
}

func LookupOCPVersion(operatorName, operatorVersion string) string {
	mappings, ok := operatorMappings[operatorName]
	if !ok {
		return ""
	}

	normalizedVersion := normalizeVersion(operatorVersion)

	for _, m := range mappings {
		if normalizeVersion(m.OperatorVersion) == normalizedVersion {
			if len(m.OCPVersions) > 0 {
				return m.OCPVersions[len(m.OCPVersions)-1]
			}
		}
	}
	return ""
}

func LookupSupportPhase(ocpVersion string) types.SupportPhase {
	return LookupSupportPhaseAt(ocpVersion, time.Now())
}

func LookupSupportPhaseAt(ocpVersion string, at time.Time) types.SupportPhase {
	for _, r := range ocpReleases {
		if r.Version != ocpVersion {
			continue
		}

		if at.Before(r.GA) {
			return types.PhaseUnknown
		}
		if at.Before(r.EndFullSupport) {
			return types.PhaseGA
		}
		if at.Before(r.EndMaintenance) {
			return types.PhaseMaintenance
		}
		if r.EUS {
			if !r.EndEUS1.IsZero() && at.Before(r.EndEUS1) {
				return types.PhaseEUS1
			}
			if !r.EndEUS2.IsZero() && at.Before(r.EndEUS2) {
				return types.PhaseEUS2
			}
		}
		return types.PhaseEOL
	}
	return types.PhaseUnknown
}

func SupportedOperatorVersions(operatorName string) []string {
	mappings, ok := operatorMappings[operatorName]
	if !ok {
		return nil
	}
	var versions []string
	for _, m := range mappings {
		ocpVersion := ""
		if len(m.OCPVersions) > 0 {
			ocpVersion = m.OCPVersions[len(m.OCPVersions)-1]
		}
		phase := LookupSupportPhase(ocpVersion)
		if phase != types.PhaseEOL {
			versions = append(versions, m.OperatorVersion)
		}
	}
	return versions
}

func AllOCPVersionsForOperator(operatorName, operatorVersion string) []string {
	mappings, ok := operatorMappings[operatorName]
	if !ok {
		return nil
	}

	normalizedVersion := normalizeVersion(operatorVersion)
	for _, m := range mappings {
		if normalizeVersion(m.OperatorVersion) == normalizedVersion {
			return m.OCPVersions
		}
	}
	return nil
}

func BuildOCPSupport(operatorName, operatorVersion string) []string {
	return BuildOCPSupportAt(operatorName, operatorVersion, time.Now())
}

func BuildOCPSupportAt(operatorName, operatorVersion string, at time.Time) []string {
	ocpVersions := AllOCPVersionsForOperator(operatorName, operatorVersion)
	if len(ocpVersions) == 0 {
		return nil
	}

	if len(ocpVersions) == 1 {
		r := findRelease(ocpVersions[0])
		if r == nil {
			return nil
		}
		return []string{formatPlatformAligned(r, []string{r.Version}, at)}
	}

	paVersion := ocpVersions[len(ocpVersions)-1]
	rsVersions := ocpVersions[:len(ocpVersions)-1]

	paRelease := findRelease(paVersion)
	if paRelease == nil {
		return nil
	}

	lastRS := findRelease(rsVersions[len(rsVersions)-1])

	var entries []string

	if lastRS != nil {
		rsPhase := rollingStreamPhase(paRelease.EndFullSupport, lastRS.EndMaintenance, at)
		var phaseEnd string
		switch rsPhase {
		case types.PhaseGA:
			phaseEnd = paRelease.EndFullSupport.Format(dateFmt)
		case types.PhaseMaintenance:
			phaseEnd = lastRS.EndMaintenance.Format(dateFmt)
		case types.PhaseEOL:
			phaseEnd = "EOL"
		}
		entries = append(entries, fmt.Sprintf("Rolling Stream OCP %s: %s until %s, EOL %s (%s)",
			strings.Join(rsVersions, ", "), rsPhase, phaseEnd,
			lastRS.EndMaintenance.Format(dateFmt), ocpSupportSource))
	}

	entries = append(entries, formatPlatformAligned(paRelease, []string{paVersion}, at))

	return entries
}

const (
	dateFmt          = "2006-01-02"
	ocpSupportSource = "https://access.redhat.com/support/policy/updates/openshift_operators#platform-aligned"
)

func formatPlatformAligned(r *OCPRelease, versions []string, at time.Time) string {
	phase := LookupSupportPhaseAt(r.Version, at)

	var phaseEnd string
	switch phase {
	case types.PhaseGA:
		phaseEnd = r.EndFullSupport.Format(dateFmt)
	case types.PhaseMaintenance:
		phaseEnd = r.EndMaintenance.Format(dateFmt)
	case types.PhaseEUS1:
		phaseEnd = r.EndEUS1.Format(dateFmt)
	case types.PhaseEUS2:
		phaseEnd = r.EndEUS2.Format(dateFmt)
	case types.PhaseEOL:
		phaseEnd = "EOL"
	}

	var eol string
	if r.EUS && !r.EndEUS2.IsZero() {
		eol = r.EndEUS2.Format(dateFmt)
	} else if r.EUS && !r.EndEUS1.IsZero() {
		eol = r.EndEUS1.Format(dateFmt)
	} else {
		eol = r.EndMaintenance.Format(dateFmt)
	}

	return fmt.Sprintf("Platform Aligned OCP %s: %s until %s, EOL %s (%s)",
		strings.Join(versions, ", "), phase, phaseEnd, eol, ocpSupportSource)
}

func rollingStreamPhase(endFullSupport, endMaintenance time.Time, at time.Time) types.SupportPhase {
	if at.Before(endFullSupport) {
		return types.PhaseGA
	}
	if at.Before(endMaintenance) {
		return types.PhaseMaintenance
	}
	return types.PhaseEOL
}

func findRelease(version string) *OCPRelease {
	for i := range ocpReleases {
		if ocpReleases[i].Version == version {
			return &ocpReleases[i]
		}
	}
	return nil
}

func FormatSupportInfo(operatorName, operatorVersion string) string {
	entries := BuildOCPSupport(operatorName, operatorVersion)
	if len(entries) == 0 {
		return ""
	}
	return strings.Join(entries, "; ")
}

// RHWA release version → OCP version mapping
// e.g., rhwa-24.2 ships with OCP 4.16, rhwa-25.1 ships with OCP 4.18
// RHWA release → OCP version mapping (latest OCP in range).
// Skips Konflux migration releases (rhwa-25.2 through 25.7).
// For multi-OCP entries, maps to the latest for lifecycle lookup.
var rhwaToOCP = map[string]string{
	"rhwa-25.1":   "4.18",
	"rhwa-25.8":   "4.20",
	"rhwa-25.9":   "4.20",
	"rhwa-26.1":   "4.20",
	"rhwa-26.2":   "4.21",
	"rhwa-4.21-0": "4.21",
	"rhwa-4.22-0": "4.22",
}

var ocpVersionRe = regexp.MustCompile(`^(?:OpenShift|OCP)\s+(4\.\d+)$`)

func LookupOperatorVersionFromRHWA(operatorName, rhwaVersion string) string {
	ocpVersion, ok := rhwaToOCP[rhwaVersion]
	if !ok {
		if m := ocpVersionRe.FindStringSubmatch(rhwaVersion); len(m) == 2 {
			ocpVersion = m[1]
		} else {
			return ""
		}
	}

	mappings, ok := operatorMappings[operatorName]
	if !ok {
		return ""
	}

	for _, m := range mappings {
		for _, ocp := range m.OCPVersions {
			if ocp == ocpVersion {
				return m.OperatorVersion
			}
		}
	}
	return ""
}

func normalizeVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return v
}

func date(year int, month time.Month, day int) time.Time {
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

func SetConfig(releases []OCPRelease, mappings map[string][]OperatorOCPMapping, rhwa map[string]string) {
	ocpReleases = releases
	operatorMappings = mappings
	rhwaToOCP = rhwa
}

func ConfigFromYAML(cfg config.LifecycleConfig) ([]OCPRelease, map[string][]OperatorOCPMapping, map[string]string, error) {
	releases, err := parseOCPReleases(cfg.OCPReleases)
	if err != nil {
		return nil, nil, nil, err
	}

	mappings := make(map[string][]OperatorOCPMapping, len(cfg.OperatorMappings))
	for name, cfgMappings := range cfg.OperatorMappings {
		converted := make([]OperatorOCPMapping, len(cfgMappings))
		for i, m := range cfgMappings {
			converted[i] = OperatorOCPMapping{
				OperatorVersion: m.OperatorVersion,
				OCPVersions:     m.OCPVersions,
			}
		}
		mappings[name] = converted
	}

	return releases, mappings, cfg.RHWAToOCP, nil
}

func parseOCPReleases(cfgReleases []config.OCPReleaseConfig) ([]OCPRelease, error) {
	releases := make([]OCPRelease, len(cfgReleases))
	for i, cr := range cfgReleases {
		ga, err := parseDate(cr.GA)
		if err != nil {
			return nil, fmt.Errorf("release %s ga: %w", cr.Version, err)
		}
		endFull, err := parseDate(cr.EndFullSupport)
		if err != nil {
			return nil, fmt.Errorf("release %s end_full_support: %w", cr.Version, err)
		}
		endMaint, err := parseDate(cr.EndMaintenance)
		if err != nil {
			return nil, fmt.Errorf("release %s end_maintenance: %w", cr.Version, err)
		}

		r := OCPRelease{
			Version:        cr.Version,
			GA:             ga,
			EndFullSupport: endFull,
			EndMaintenance: endMaint,
			EUS:            cr.EUS,
		}

		if cr.EndEUS1 != "" {
			eus1, err := parseDate(cr.EndEUS1)
			if err != nil {
				return nil, fmt.Errorf("release %s end_eus1: %w", cr.Version, err)
			}
			r.EndEUS1 = eus1
		}
		if cr.EndEUS2 != "" {
			eus2, err := parseDate(cr.EndEUS2)
			if err != nil {
				return nil, fmt.Errorf("release %s end_eus2: %w", cr.Version, err)
			}
			r.EndEUS2 = eus2
		}

		releases[i] = r
	}
	return releases, nil
}

func parseDate(s string) (time.Time, error) {
	return time.Parse(dateFmt, s)
}
