package lifecycle

import (
	"fmt"
	"strings"
	"time"

	"github.com/razo7/vigil/pkg/types"
)

type OCPRelease struct {
	Version            string
	GA                 time.Time
	EndFullSupport     time.Time
	EndMaintenance     time.Time
	EUS                bool
	EndEUS             time.Time
}

type OperatorOCPMapping struct {
	OperatorVersion string
	OCPVersions     []string
}

var ocpReleases = []OCPRelease{
	{Version: "4.12", GA: date(2023, 1, 17), EndFullSupport: date(2023, 7, 17), EndMaintenance: date(2024, 7, 17), EUS: true, EndEUS: date(2025, 1, 17)},
	{Version: "4.13", GA: date(2023, 5, 17), EndFullSupport: date(2023, 11, 17), EndMaintenance: date(2024, 11, 17)},
	{Version: "4.14", GA: date(2023, 10, 31), EndFullSupport: date(2024, 6, 18), EndMaintenance: date(2025, 5, 1), EUS: true, EndEUS: date(2025, 10, 31)},
	{Version: "4.15", GA: date(2024, 2, 27), EndFullSupport: date(2024, 10, 16), EndMaintenance: date(2025, 8, 27)},
	{Version: "4.16", GA: date(2024, 6, 27), EndFullSupport: date(2025, 1, 30), EndMaintenance: date(2025, 12, 27), EUS: true, EndEUS: date(2026, 6, 27)},
	{Version: "4.17", GA: date(2024, 10, 10), EndFullSupport: date(2025, 6, 11), EndMaintenance: date(2026, 4, 1)},
	{Version: "4.18", GA: date(2025, 3, 11), EndFullSupport: date(2025, 10, 28), EndMaintenance: date(2026, 8, 25), EUS: true, EndEUS: date(2027, 3, 11)},
	{Version: "4.19", GA: date(2025, 6, 25), EndFullSupport: date(2026, 2, 18), EndMaintenance: date(2026, 12, 17)},
	{Version: "4.20", GA: date(2025, 11, 5), EndFullSupport: date(2026, 6, 1), EndMaintenance: date(2027, 5, 5), EUS: true, EndEUS: date(2027, 11, 5)},
	{Version: "4.21", GA: date(2026, 3, 25), EndFullSupport: date(2026, 10, 25), EndMaintenance: date(2027, 9, 25)},
}

var operatorMappings = map[string][]OperatorOCPMapping{
	"fence-agents-remediation": {
		{OperatorVersion: "0.2", OCPVersions: []string{"4.14"}},
		{OperatorVersion: "0.4", OCPVersions: []string{"4.16"}},
		{OperatorVersion: "0.5", OCPVersions: []string{"4.18"}},
		{OperatorVersion: "0.6", OCPVersions: []string{"4.16", "4.17", "4.18", "4.19", "4.20"}},
		{OperatorVersion: "0.7", OCPVersions: []string{"4.21"}},
	},
	"self-node-remediation": {
		{OperatorVersion: "0.5", OCPVersions: []string{"4.12"}},
		{OperatorVersion: "0.7", OCPVersions: []string{"4.14"}},
		{OperatorVersion: "0.9", OCPVersions: []string{"4.16"}},
		{OperatorVersion: "0.10", OCPVersions: []string{"4.14", "4.15", "4.16", "4.17", "4.18", "4.19"}},
		{OperatorVersion: "0.11", OCPVersions: []string{"4.16", "4.17", "4.18", "4.19", "4.20"}},
		{OperatorVersion: "0.12", OCPVersions: []string{"4.21"}},
	},
	"node-healthcheck-controller": {
		{OperatorVersion: "0.4", OCPVersions: []string{"4.12"}},
		{OperatorVersion: "0.6", OCPVersions: []string{"4.14"}},
		{OperatorVersion: "0.8", OCPVersions: []string{"4.16"}},
		{OperatorVersion: "0.9", OCPVersions: []string{"4.18"}},
		{OperatorVersion: "0.10", OCPVersions: []string{"4.16", "4.17", "4.18", "4.19", "4.20"}},
		{OperatorVersion: "0.11", OCPVersions: []string{"4.21"}},
	},
	"node-maintenance-operator": {
		{OperatorVersion: "5.0", OCPVersions: []string{"4.12"}},
		{OperatorVersion: "5.2", OCPVersions: []string{"4.14"}},
		{OperatorVersion: "5.3", OCPVersions: []string{"4.16"}},
		{OperatorVersion: "5.4", OCPVersions: []string{"4.14", "4.15", "4.16", "4.17", "4.18", "4.19"}},
		{OperatorVersion: "5.5", OCPVersions: []string{"4.16", "4.17", "4.18", "4.19", "4.20"}},
		{OperatorVersion: "5.6", OCPVersions: []string{"4.21"}},
	},
	"machine-deletion-remediation": {
		{OperatorVersion: "0.2", OCPVersions: []string{"4.14"}},
		{OperatorVersion: "0.3", OCPVersions: []string{"4.16"}},
		{OperatorVersion: "0.4", OCPVersions: []string{"4.14", "4.15", "4.16", "4.17", "4.18", "4.19"}},
		{OperatorVersion: "0.5", OCPVersions: []string{"4.16", "4.17", "4.18", "4.19", "4.20"}},
		{OperatorVersion: "0.6", OCPVersions: []string{"4.21"}},
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
		if r.EUS && at.Before(r.EndMaintenance) {
			return types.PhaseEUS1
		}
		if at.Before(r.EndMaintenance) {
			return types.PhaseMaintenance
		}
		if r.EUS && at.Before(r.EndEUS) {
			return types.PhaseEUS2
		}
		return types.PhaseEOL
	}
	return types.PhaseUnknown
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

func FormatSupportInfo(operatorName, operatorVersion string) string {
	ocpVersions := AllOCPVersionsForOperator(operatorName, operatorVersion)
	if len(ocpVersions) == 0 {
		return ""
	}

	var parts []string
	for _, ocp := range ocpVersions {
		phase := LookupSupportPhase(ocp)
		parts = append(parts, fmt.Sprintf("%s (%s)", ocp, phase))
	}
	return strings.Join(parts, ", ")
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
