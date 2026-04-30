package fix

import (
	"fmt"
	"os/exec"
	"strings"
)

type replaceStrategy struct{}

func (s *replaceStrategy) Name() StrategyName { return StrategyReplace }
func (s *replaceStrategy) Risk() int          { return 3 }

func (s *replaceStrategy) Apply(opts StrategyOptions) (*StrategyResult, error) {
	if opts.Package == "" || opts.FixVersion == "" {
		return nil, fmt.Errorf("package and fix version required for replace strategy")
	}

	version := opts.FixVersion
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	replacement := fmt.Sprintf("%s=%s@%s", opts.Package, opts.Package, version)
	command := fmt.Sprintf("go mod edit -replace %s", replacement)

	if opts.DryRun {
		return &StrategyResult{
			Strategy: StrategyReplace,
			Risk:     3,
			Command:  command,
			Message:  fmt.Sprintf("Would add replace directive: %s => %s@%s", opts.Package, opts.Package, version),
		}, nil
	}

	cmd := exec.Command("go", "mod", "edit", "-replace", replacement)
	cmd.Dir = opts.RepoPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", command, truncate(string(output), 300), err)
	}

	return &StrategyResult{
		Strategy: StrategyReplace,
		Risk:     3,
		Command:  command,
		Changes:  []string{"go.mod"},
		Message:  fmt.Sprintf("Added replace directive: %s => %s@%s", opts.Package, opts.Package, version),
	}, nil
}
