package fix

import (
	"fmt"
	"os/exec"
	"strings"
)

type majorStrategy struct {
	Approved bool
}

func (s *majorStrategy) Name() StrategyName { return StrategyMajor }
func (s *majorStrategy) Risk() int          { return 4 }

func (s *majorStrategy) Apply(opts StrategyOptions) (*StrategyResult, error) {
	if !s.Approved {
		return nil, fmt.Errorf("major version bump requires --approve-major flag (risk 4: changes import paths)")
	}

	if opts.Package == "" || opts.FixVersion == "" {
		return nil, fmt.Errorf("package and fix version required for major strategy")
	}

	version := opts.FixVersion
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	target := fmt.Sprintf("%s@%s", opts.Package, version)
	command := fmt.Sprintf("go get %s (major version bump)", target)

	if opts.DryRun {
		return &StrategyResult{
			Strategy: StrategyMajor,
			Risk:     4,
			Command:  command,
			Message:  fmt.Sprintf("Would perform major version bump of %s to %s (import paths may change)", opts.Package, version),
		}, nil
	}

	cmd := exec.Command("go", "get", target)
	cmd.Dir = opts.RepoPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", command, truncate(string(output), 300), err)
	}

	return &StrategyResult{
		Strategy: StrategyMajor,
		Risk:     4,
		Command:  command,
		Changes:  []string{"go.mod", "go.sum"},
		Message:  fmt.Sprintf("Major version bump of %s to %s", opts.Package, version),
	}, nil
}
