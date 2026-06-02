package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Jira         JiraConfig                 `yaml:"jira"`
	Components   map[string]ComponentConfig `yaml:"components"`
	Lifecycle    LifecycleConfig            `yaml:"lifecycle"`
	EOLThreshold string                     `yaml:"eol_threshold"`
}

func (c *Config) EOLThresholdDuration() time.Duration {
	s := c.EOLThreshold
	if s == "" || s == "0" {
		return 0
	}
	s = strings.TrimSpace(s)
	defaultDur := 90 * 24 * time.Hour
	if strings.HasSuffix(s, "d") {
		days := 0
		fmt.Sscanf(s, "%dd", &days)
		if days > 0 {
			return time.Duration(days) * 24 * time.Hour
		}
		return defaultDur
	}
	if strings.HasSuffix(s, "m") {
		months := 0
		fmt.Sscanf(s, "%dm", &months)
		if months > 0 {
			return time.Duration(months) * 30 * 24 * time.Hour
		}
		return defaultDur
	}
	if strings.HasSuffix(s, "y") {
		years := 0
		fmt.Sscanf(s, "%dy", &years)
		if years > 0 {
			return time.Duration(years) * 365 * 24 * time.Hour
		}
		return defaultDur
	}
	return defaultDur
}

type LifecycleConfig struct {
	OCPReleases      []OCPReleaseConfig          `yaml:"ocp_releases"`
	OperatorMappings map[string][]OperatorMapping `yaml:"operator_mappings"`
	RHWAToOCP        map[string]string            `yaml:"rhwa_to_ocp"`
}

type OCPReleaseConfig struct {
	Version        string `yaml:"version"`
	GA             string `yaml:"ga"`
	EndFullSupport string `yaml:"end_full_support"`
	EndMaintenance string `yaml:"end_maintenance"`
	EUS            bool   `yaml:"eus"`
	EndEUS1        string `yaml:"end_eus1,omitempty"`
	EndEUS2        string `yaml:"end_eus2,omitempty"`
}

type OperatorMapping struct {
	OperatorVersion string   `yaml:"operator_version"`
	OCPVersions     []string `yaml:"ocp_versions"`
}

type JiraConfig struct {
	BaseURL  string   `yaml:"base_url"`
	Projects []string `yaml:"projects"`
}

func (j JiraConfig) ProjectJQL() string {
	if len(j.Projects) == 0 {
		return "project in (RHWA, ECOPROJECT)"
	}
	if len(j.Projects) == 1 {
		return fmt.Sprintf("project = %s", j.Projects[0])
	}
	return fmt.Sprintf("project in (%s)", strings.Join(j.Projects, ", "))
}

func (j JiraConfig) BrowseURL(ticketID string) string {
	base := j.BaseURL
	if base == "" {
		base = "https://redhat.atlassian.net"
	}
	return fmt.Sprintf("%s/browse/%s", strings.TrimRight(base, "/"), ticketID)
}

type ComponentConfig struct {
	JiraName     string            `yaml:"jira_name"`
	OperatorName string            `yaml:"operator_name"`
	Repo         string            `yaml:"repo,omitempty"`
	HealthIndex  map[string]string `yaml:"health_index,omitempty"`
	DownstreamGo map[string]string `yaml:"downstream_go,omitempty"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return &cfg, nil
}

func Default() *Config {
	return &Config{
		Jira: JiraConfig{
			BaseURL:  "https://redhat.atlassian.net",
			Projects: []string{"RHWA", "ECOPROJECT"},
		},
		Components: map[string]ComponentConfig{
			"far": {
				JiraName:     "Fence Agents Remediation",
				OperatorName: "fence-agents-remediation",
				Repo:         "github.com/medik8s/fence-agents-remediation",
			},
			"snr": {
				JiraName:     "Self Node Remediation",
				OperatorName: "self-node-remediation",
				Repo:         "github.com/medik8s/self-node-remediation",
			},
			"nhc": {
				JiraName:     "Node Healthcheck",
				OperatorName: "node-healthcheck-operator",
				Repo:         "github.com/medik8s/node-healthcheck-operator",
			},
			"nmo": {
				JiraName:     "Node Maintenance Operator",
				OperatorName: "node-maintenance-operator",
				Repo:         "github.com/medik8s/node-maintenance-operator",
			},
			"mdr": {
				JiraName:     "Machine Deletion Remediation",
				OperatorName: "machine-deletion-remediation",
				Repo:         "github.com/medik8s/machine-deletion-remediation",
			},
			"sbr": {
				JiraName:     "Storage-based Remediation",
				OperatorName: "storage-based-remediation",
				Repo:         "github.com/medik8s/storage-based-remediation",
			},
			"nhc-console": {
				JiraName:     "Node Remediation Console",
				OperatorName: "node-remediation-console",
				Repo:         "github.com/medik8s/node-remediation-console",
			},
		},
		Lifecycle: DefaultLifecycle(),
	}
}

func DefaultLifecycle() LifecycleConfig {
	return LifecycleConfig{
		OCPReleases: []OCPReleaseConfig{
			{Version: "4.12", GA: "2023-01-17", EndFullSupport: "2023-07-17", EndMaintenance: "2024-07-17", EUS: true, EndEUS1: "2025-01-17"},
			{Version: "4.13", GA: "2023-05-17", EndFullSupport: "2023-11-17", EndMaintenance: "2024-11-17"},
			{Version: "4.14", GA: "2023-10-31", EndFullSupport: "2024-02-20", EndMaintenance: "2025-05-01", EUS: true, EndEUS1: "2025-10-31", EndEUS2: "2026-10-31"},
			{Version: "4.15", GA: "2024-02-27", EndFullSupport: "2024-10-16", EndMaintenance: "2025-08-27"},
			{Version: "4.16", GA: "2024-06-27", EndFullSupport: "2025-01-21", EndMaintenance: "2025-12-27", EUS: true, EndEUS1: "2026-06-27", EndEUS2: "2027-06-27"},
			{Version: "4.17", GA: "2024-10-10", EndFullSupport: "2025-05-25", EndMaintenance: "2026-04-01"},
			{Version: "4.18", GA: "2025-03-11", EndFullSupport: "2025-09-16", EndMaintenance: "2026-08-25", EUS: true, EndEUS1: "2027-02-25", EndEUS2: "2028-02-25"},
			{Version: "4.19", GA: "2025-06-25", EndFullSupport: "2026-05-03", EndMaintenance: "2026-12-17"},
			{Version: "4.20", GA: "2025-11-05", EndFullSupport: "2026-05-03", EndMaintenance: "2027-04-21", EUS: true, EndEUS1: "2027-10-21", EndEUS2: "2028-10-21"},
			{Version: "4.21", GA: "2026-03-25", EndFullSupport: "2026-10-25", EndMaintenance: "2027-09-25"},
		},
		OperatorMappings: map[string][]OperatorMapping{
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
			"node-healthcheck-operator": {
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
		},
		RHWAToOCP: map[string]string{
			"rhwa-23.3": "4.14",
			"rhwa-24.1": "4.15",
			"rhwa-24.2": "4.16",
			"rhwa-24.3": "4.17",
			"rhwa-25.1": "4.18",
			"rhwa-25.2": "4.19",
			"rhwa-25.3": "4.20",
			"rhwa-26.1": "4.21",
		},
	}
}

func (c *Config) ComponentMap() map[string]string {
	m := make(map[string]string, len(c.Components))
	for short, comp := range c.Components {
		m[strings.ToLower(short)] = comp.JiraName
	}
	return m
}

func (c *Config) OperatorNames() map[string]string {
	m := make(map[string]string, len(c.Components))
	for short, comp := range c.Components {
		m[strings.ToUpper(short)] = comp.OperatorName
	}
	return m
}
