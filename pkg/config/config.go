package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Components map[string]ComponentConfig `yaml:"components"`
}

type ComponentConfig struct {
	JiraName     string `yaml:"jira_name"`
	OperatorName string `yaml:"operator_name"`
	Repo         string `yaml:"repo,omitempty"`
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
