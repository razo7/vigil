package goversion

import (
	"fmt"
	"strings"

	"github.com/razo7/vigil/pkg/classify"
	"github.com/razo7/vigil/pkg/downstream"
)

type CheckResult struct {
	Operator          string `json:"operator"`
	DesiredVersion    string `json:"desired_version"`
	DownstreamVersion string `json:"downstream_version"`
	Branch            string `json:"branch"`
	Available         bool   `json:"available"`
}

func CheckGoVersion(operatorName, desiredVersion, imageName, operatorVersion string) (*CheckResult, error) {
	info, err := downstream.FetchGoVersionForOperator(operatorName, imageName, operatorVersion)
	if err != nil {
		return nil, fmt.Errorf("fetching downstream Go version for %s: %w", operatorName, err)
	}

	dsVersion := strings.TrimPrefix(info.GoVersion, "go")
	dsVersion = strings.TrimPrefix(dsVersion, "v")
	desired := strings.TrimPrefix(desiredVersion, "go")
	desired = strings.TrimPrefix(desired, "v")

	available := classify.CompareVersions(dsVersion, desired) >= 0

	return &CheckResult{
		Operator:          operatorName,
		DesiredVersion:    desired,
		DownstreamVersion: dsVersion,
		Branch:            info.Branch,
		Available:         available,
	}, nil
}
