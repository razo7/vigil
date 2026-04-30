package fix

import (
	"fmt"
	"os/exec"
	"strings"
)

type transitiveStrategy struct{}

func (s *transitiveStrategy) Name() StrategyName { return StrategyTransitive }
func (s *transitiveStrategy) Risk() int          { return 2 }

func (s *transitiveStrategy) Apply(opts StrategyOptions) (*StrategyResult, error) {
	if opts.Package == "" || opts.FixVersion == "" {
		return nil, fmt.Errorf("package and fix version required for transitive strategy")
	}

	parent, err := findDirectParent(opts.RepoPath, opts.Package)
	if err != nil {
		return nil, fmt.Errorf("finding direct parent of %s: %w", opts.Package, err)
	}

	version := opts.FixVersion
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	target := fmt.Sprintf("%s@%s", parent, version)
	command := fmt.Sprintf("go get %s (parent of %s)", target, opts.Package)

	if opts.DryRun {
		return &StrategyResult{
			Strategy: StrategyTransitive,
			Risk:     2,
			Command:  command,
			Message:  fmt.Sprintf("Would bump parent dependency %s to pull in fix for %s", parent, opts.Package),
		}, nil
	}

	cmd := exec.Command("go", "get", target)
	cmd.Dir = opts.RepoPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", command, truncate(string(output), 300), err)
	}

	return &StrategyResult{
		Strategy: StrategyTransitive,
		Risk:     2,
		Command:  command,
		Changes:  []string{"go.mod", "go.sum"},
		Message:  fmt.Sprintf("Bumped parent %s to pull in fix for %s", parent, opts.Package),
	}, nil
}

func findDirectParent(repoPath, pkg string) (string, error) {
	cmd := exec.Command("go", "mod", "graph")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go mod graph: %w", err)
	}

	graph := parseModGraph(string(output))

	parents, ok := graph[pkg]
	if !ok {
		for mod := range graph {
			if strings.HasPrefix(mod, pkg+"@") || strings.HasPrefix(pkg, mod) {
				parents = graph[mod]
				break
			}
		}
	}

	if len(parents) == 0 {
		return "", fmt.Errorf("no parent found for %s in dependency graph", pkg)
	}

	modulePath := readModulePath(repoPath)

	for _, p := range parents {
		name := stripVersion(p)
		if name == modulePath {
			return pkg, nil
		}
	}

	return stripVersion(parents[0]), nil
}

func parseModGraph(output string) map[string][]string {
	graph := make(map[string][]string)
	for _, line := range strings.Split(output, "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		child := stripVersion(parts[1])
		graph[child] = append(graph[child], parts[0])
	}
	return graph
}

func stripVersion(mod string) string {
	if idx := strings.LastIndex(mod, "@"); idx != -1 {
		return mod[:idx]
	}
	return mod
}

func readModulePath(repoPath string) string {
	cmd := exec.Command("go", "list", "-m")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}
