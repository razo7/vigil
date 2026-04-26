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

var registryImages = map[string][]string{
	"fence-agents-remediation": {
		"registry.redhat.io/workload-availability/fence-agents-remediation-rhel9-operator",
		"registry.redhat.io/workload-availability/fence-agents-remediation-rhel8-operator",
	},
	"self-node-remediation": {
		"registry.redhat.io/workload-availability/self-node-remediation-rhel9-operator",
		"registry.redhat.io/workload-availability/self-node-remediation-rhel8-operator",
	},
	"node-healthcheck-controller": {
		"registry.redhat.io/workload-availability/node-healthcheck-rhel9-operator",
		"registry.redhat.io/workload-availability/node-healthcheck-rhel8-operator",
	},
	"node-maintenance-operator": {
		"registry.redhat.io/workload-availability/node-maintenance-rhel9-operator",
		"registry.redhat.io/workload-availability/node-maintenance-rhel8-operator",
	},
	"machine-deletion-remediation": {
		"registry.redhat.io/workload-availability/machine-deletion-remediation-rhel9-operator",
		"registry.redhat.io/workload-availability/machine-deletion-remediation-rhel8-operator",
	},
}

var versionTagRe = regexp.MustCompile(`^v?(\d+\.\d+(?:\.\d+)?)$`)

func LookupDownstreamComponent(operatorName, operatorVersion string) (*DownstreamComponent, error) {
	images, ok := registryImages[operatorName]
	if !ok {
		return nil, fmt.Errorf("no registry images configured for %s", operatorName)
	}

	normalizedVersion := strings.TrimPrefix(operatorVersion, "v")

	for _, image := range images {
		tags, err := skopeoListTags(image)
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
				name := image[strings.LastIndex(image, "/")+1:]
				rhelBase := "rhel9"
				if strings.Contains(image, "rhel8") {
					rhelBase = "rhel8"
				}
				catalogURL := fmt.Sprintf("https://catalog.redhat.com/software/containers/search?q=%s", name)
				return &DownstreamComponent{
					Name:       name,
					Registry:   image,
					RHELBase:   rhelBase,
					MatchedTag: tag,
					CatalogURL: catalogURL,
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
