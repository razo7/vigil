package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if len(cfg.Components) == 0 {
		t.Fatal("Default() returned empty components")
	}
	far, ok := cfg.Components["far"]
	if !ok {
		t.Fatal("Default() missing 'far' component")
	}
	if far.JiraName != "Fence Agents Remediation" {
		t.Errorf("far.JiraName = %q, want %q", far.JiraName, "Fence Agents Remediation")
	}
	if far.OperatorName != "fence-agents-remediation" {
		t.Errorf("far.OperatorName = %q, want %q", far.OperatorName, "fence-agents-remediation")
	}
}

func TestComponentMap(t *testing.T) {
	cfg := Default()
	m := cfg.ComponentMap()
	if m["far"] != "Fence Agents Remediation" {
		t.Errorf("ComponentMap()[far] = %q, want %q", m["far"], "Fence Agents Remediation")
	}
	if m["nhc-console"] != "Node Remediation Console" {
		t.Errorf("ComponentMap()[nhc-console] = %q, want %q", m["nhc-console"], "Node Remediation Console")
	}
}

func TestOperatorNames(t *testing.T) {
	cfg := Default()
	m := cfg.OperatorNames()
	if m["FAR"] != "fence-agents-remediation" {
		t.Errorf("OperatorNames()[FAR] = %q, want %q", m["FAR"], "fence-agents-remediation")
	}
	if m["NHC-CONSOLE"] != "node-remediation-console" {
		t.Errorf("OperatorNames()[NHC-CONSOLE] = %q, want %q", m["NHC-CONSOLE"], "node-remediation-console")
	}
}

func TestLoad(t *testing.T) {
	content := `components:
  test-op:
    jira_name: "Test Operator"
    operator_name: "test-operator"
    repo: "github.com/example/test-operator"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "vigil.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Components) != 1 {
		t.Fatalf("Load() returned %d components, want 1", len(cfg.Components))
	}
	comp := cfg.Components["test-op"]
	if comp.JiraName != "Test Operator" {
		t.Errorf("JiraName = %q, want %q", comp.JiraName, "Test Operator")
	}
	if comp.OperatorName != "test-operator" {
		t.Errorf("OperatorName = %q, want %q", comp.OperatorName, "test-operator")
	}
	if comp.Repo != "github.com/example/test-operator" {
		t.Errorf("Repo = %q, want %q", comp.Repo, "github.com/example/test-operator")
	}
}

func TestDefaultJira(t *testing.T) {
	cfg := Default()
	if cfg.Jira.BaseURL != "https://redhat.atlassian.net" {
		t.Errorf("Jira.BaseURL = %q, want redhat.atlassian.net", cfg.Jira.BaseURL)
	}
	if len(cfg.Jira.Projects) != 2 {
		t.Fatalf("Jira.Projects has %d entries, want 2", len(cfg.Jira.Projects))
	}
	if cfg.Jira.ProjectJQL() != "project in (RHWA, ECOPROJECT)" {
		t.Errorf("ProjectJQL() = %q", cfg.Jira.ProjectJQL())
	}
	if cfg.Jira.BrowseURL("TEST-1") != "https://redhat.atlassian.net/browse/TEST-1" {
		t.Errorf("BrowseURL() = %q", cfg.Jira.BrowseURL("TEST-1"))
	}
}

func TestJiraSingleProject(t *testing.T) {
	cfg := &Config{Jira: JiraConfig{Projects: []string{"MYPROJ"}}}
	if cfg.Jira.ProjectJQL() != "project = MYPROJ" {
		t.Errorf("ProjectJQL() = %q, want single project syntax", cfg.Jira.ProjectJQL())
	}
}

func TestJiraCustomURL(t *testing.T) {
	cfg := &Config{Jira: JiraConfig{BaseURL: "https://jira.example.com"}}
	got := cfg.Jira.BrowseURL("PROJ-42")
	if got != "https://jira.example.com/browse/PROJ-42" {
		t.Errorf("BrowseURL() = %q", got)
	}
}

func TestLoadWithJira(t *testing.T) {
	content := `jira:
  base_url: "https://jira.example.com"
  projects:
    - MYPROJ
components:
  myop:
    jira_name: "My Operator"
    operator_name: "my-operator"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "vigil.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Jira.BaseURL != "https://jira.example.com" {
		t.Errorf("Jira.BaseURL = %q", cfg.Jira.BaseURL)
	}
	if cfg.Jira.ProjectJQL() != "project = MYPROJ" {
		t.Errorf("ProjectJQL() = %q", cfg.Jira.ProjectJQL())
	}
}

func TestEOLThreshold(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"", 0},
		{"0", 0},
		{"30d", 30 * 24 * time.Hour},
		{"90d", 90 * 24 * time.Hour},
		{"6m", 180 * 24 * time.Hour},
		{"1y", 365 * 24 * time.Hour},
		{"invalid", 90 * 24 * time.Hour},
	}
	for _, tt := range tests {
		cfg := &Config{EOLThreshold: tt.input}
		got := cfg.EOLThresholdDuration()
		if got != tt.expected {
			t.Errorf("EOLThresholdDuration(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/vigil.yaml")
	if err == nil {
		t.Fatal("Load() should return error for missing file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("{{invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() should return error for invalid YAML")
	}
}
