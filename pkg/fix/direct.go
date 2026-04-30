package fix

import (
	"fmt"
	"os/exec"
	"strings"
)

type directStrategy struct{}

func (s *directStrategy) Name() StrategyName { return StrategyDirect }
func (s *directStrategy) Risk() int          { return 1 }

func (s *directStrategy) Apply(opts StrategyOptions) (*StrategyResult, error) {
	if opts.Package == "" || opts.FixVersion == "" {
		return nil, fmt.Errorf("package and fix version required for direct strategy")
	}

	version := opts.FixVersion
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	target := fmt.Sprintf("%s@%s", opts.Package, version)
	command := fmt.Sprintf("go get %s", target)

	if opts.DryRun {
		return &StrategyResult{
			Strategy: StrategyDirect,
			Risk:     1,
			Command:  command,
			Message:  fmt.Sprintf("Would run: %s", command),
		}, nil
	}

	cmd := exec.Command("go", "get", target)
	cmd.Dir = opts.RepoPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", command, truncate(string(output), 300), err)
	}

	return &StrategyResult{
		Strategy: StrategyDirect,
		Risk:     1,
		Command:  command,
		Changes:  []string{"go.mod", "go.sum"},
		Message:  fmt.Sprintf("Bumped %s to %s", opts.Package, version),
	}, nil
}
