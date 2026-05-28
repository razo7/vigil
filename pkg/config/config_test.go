package config

import (
	"os"
	"path/filepath"
	"testing"
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
