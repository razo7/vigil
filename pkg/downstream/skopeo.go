package downstream

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

type DownstreamComponent struct {
	Name       string
	Registry   string
	RHELBase   string
	MatchedTag string
	CatalogURL string
}

type registryImage struct {
	Image      string
	CatalogURL string
}

var registryImages = map[string][]registryImage{
	"fence-agents-remediation": {
		{"registry.redhat.io/workload-availability/fence-agents-remediation-rhel9-operator", "https://catalog.redhat.com/en/software/containers/workload-availability/fence-agents-remediation-rhel9-operator/6571618e7aa3050b63e3afab"},
		{"registry.redhat.io/workload-availability/fence-agents-remediation-rhel8-operator", "https://catalog.redhat.com/en/software/containers/workload-availability/fence-agents-remediation-rhel8-operator/63dd12aa26958ed845b46039"},
	},
	"self-node-remediation": {
		{"registry.redhat.io/workload-availability/self-node-remediation-rhel9-operator", "https://catalog.redhat.com/en/software/containers/workload-availability/self-node-remediation-rhel9-operator/6571618f4e0bd48dbce4ae45"},
		{"registry.redhat.io/workload-availability/self-node-remediation-rhel8-operator", "https://catalog.redhat.com/en/software/containers/workload-availability/self-node-remediation-rhel8-operator/619e61805e68a3498fd7f370"},
	},
	"node-healthcheck-controller": {
		{"registry.redhat.io/workload-availability/node-healthcheck-rhel9-operator", "https://catalog.redhat.com/en/software/containers/workload-availability/node-healthcheck-rhel9-operator/6571618d3be2e9f9dd11dd1f"},
		{"registry.redhat.io/workload-availability/node-healthcheck-rhel8-operator", "https://catalog.redhat.com/en/software/containers/workload-availability/node-healthcheck-rhel8-operator/6155e987fd28a8320b5a3ee0"},
	},
	"node-maintenance-operator": {
		{"registry.redhat.io/workload-availability/node-maintenance-rhel9-operator", "https://catalog.redhat.com/en/software/containers/workload-availability/node-maintenance-rhel9-operator/6571618d99fab71dc7b0d6c9"},
		{"registry.redhat.io/workload-availability/node-maintenance-rhel8-operator", "https://catalog.redhat.com/en/software/containers/workload-availability/node-maintenance-rhel8-operator/6155e3a9fd28a8320b5a3edc"},
	},
	"machine-deletion-remediation": {
		{"registry.redhat.io/workload-availability/machine-deletion-remediation-rhel9-operator", "https://catalog.redhat.com/en/software/containers/workload-availability/machine-deletion-remediation-rhel9-operator/6571618ee5ab87f6d0cb3f7e"},
		{"registry.redhat.io/workload-availability/machine-deletion-remediation-rhel8-operator", "https://catalog.redhat.com/en/software/containers/workload-availability/machine-deletion-remediation-rhel8-operator/63dd150126958ed845b46105"},
	},
}

var versionTagRe = regexp.MustCompile(`^v?(\d+\.\d+(?:\.\d+)?)$`)

func LookupDownstreamComponent(operatorName, operatorVersion string) (*DownstreamComponent, error) {
	images, ok := registryImages[operatorName]
	if !ok {
		return nil, fmt.Errorf("no registry images configured for %s", operatorName)
	}

	normalizedVersion := strings.TrimPrefix(operatorVersion, "v")

	for _, ri := range images {
		tags, err := skopeoListTags(ri.Image)
		if err != nil {
			continue
		}

		for _, tag := range tags {
			m := versionTagRe.FindStringSubmatch(tag)
			if m == nil {
				continue
			}
			tagVersion := m[1]
			if tagVersion == normalizedVersion || strings.HasPrefix(tagVersion, normalizedVersion+".") {
				name := ri.Image[strings.LastIndex(ri.Image, "/")+1:]
				rhelBase := "rhel9"
				if strings.Contains(ri.Image, "rhel8") {
					rhelBase = "rhel8"
				}
				return &DownstreamComponent{
					Name:       name,
					Registry:   ri.Image,
					RHELBase:   rhelBase,
					MatchedTag: tag,
					CatalogURL: ri.CatalogURL,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no matching tag found for %s %s", operatorName, operatorVersion)
}

func skopeoListTags(image string) ([]string, error) {
	cmd := exec.Command("skopeo", "list-tags", "docker://"+image)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("skopeo list-tags %s: %w", image, err)
	}

	var result struct {
		Tags []string `json:"Tags"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("parsing skopeo output: %w", err)
	}

	return result.Tags, nil
}
