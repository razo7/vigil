package fix

import (
	"fmt"
	"os/exec"

	"github.com/razo7/vigil/pkg/classify"
	"github.com/razo7/vigil/pkg/downstream"
)

type goMinorStrategy struct{}

func (s *goMinorStrategy) Name() StrategyName { return StrategyGoMinor }
func (s *goMinorStrategy) Risk() int          { return 0 }

func (s *goMinorStrategy) Apply(opts StrategyOptions) (*StrategyResult, error) {
	if opts.Module != "stdlib" {
		return nil, fmt.Errorf("gominor strategy only applies to stdlib CVEs (got module %q)", opts.Module)
	}

	if opts.FixVersion == "" {
		return nil, fmt.Errorf("no fix version specified")
	}

	maxGo, err := resolveMaxDownstreamGo(opts)
	if err != nil {
		return nil, fmt.Errorf("resolving max downstream Go version: %w", err)
	}

	if classify.CompareVersions(opts.FixVersion, maxGo) > 0 {
		return nil, fmt.Errorf("fix requires Go %s but latest downstream base image has %s", opts.FixVersion, maxGo)
	}

	command := fmt.Sprintf("go mod edit -go=%s", opts.FixVersion)

	if opts.DryRun {
		return &StrategyResult{
			Strategy: StrategyGoMinor,
			Risk:     0,
			Command:  command,
			Message:  fmt.Sprintf("Would bump go directive to %s (downstream has up to %s)", opts.FixVersion, maxGo),
		}, nil
	}

	cmd := exec.Command("go", "mod", "edit", "-go="+opts.FixVersion)
	cmd.Dir = opts.RepoPath
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("go mod edit -go=%s: %s: %w", opts.FixVersion, string(output), err)
	}

	return &StrategyResult{
		Strategy: StrategyGoMinor,
		Risk:     0,
		Command:  command,
		Changes:  []string{"go.mod"},
		Message:  fmt.Sprintf("Bumped go directive to %s", opts.FixVersion),
	}, nil
}

func resolveMaxDownstreamGo(opts StrategyOptions) (string, error) {
	if opts.OperatorName == "" || opts.OperatorVersion == "" {
		return "", fmt.Errorf("operator name and version required for downstream Go lookup")
	}

	info, err := downstream.FetchGoVersionForOperator(opts.OperatorName, opts.ImageName, opts.OperatorVersion)
	if err != nil {
		return "", fmt.Errorf("fetching downstream Containerfile: %w", err)
	}

	if info.GoVersion == "" {
		return "", fmt.Errorf("no Go version found in downstream Containerfile")
	}

	containerfileContent, err := downstream.FetchContainerfileContent(opts.OperatorName, opts.ImageName, opts.OperatorVersion)
	if err != nil {
		return info.GoVersion, nil
	}

	baseImage := downstream.ExtractBaseImage(containerfileContent)
	if baseImage == "" {
		return info.GoVersion, nil
	}

	latestGo, err := downstream.LatestGoVersion(baseImage)
	if err != nil {
		return info.GoVersion, nil
	}

	return latestGo, nil
}
