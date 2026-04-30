package fix

import (
	"context"
	"fmt"
	"strings"

	"github.com/razo7/vigil/pkg/assess"
	"github.com/razo7/vigil/pkg/goversion"
	"github.com/razo7/vigil/pkg/pr"
	"github.com/razo7/vigil/pkg/types"
)

func Run(ctx context.Context, opts Options) (*Result, error) {
	assessment, err := assess.Run(ctx, assess.Options{
		TicketID: opts.TicketID,
		RepoPath: opts.RepoPath,
	})
	if err != nil {
		return nil, fmt.Errorf("assessment failed: %w", err)
	}

	if assessment.Recommendation.Classification != types.FixableNow {
		return &Result{
			TicketID:   opts.TicketID,
			CVEID:      extractRaw(assessment.Vulnerability.CVEID),
			Assessment: assessment,
			DryRun:     opts.DryRun,
		}, fmt.Errorf("ticket %s classified as %q, not %q",
			opts.TicketID, assessment.Recommendation.Classification, types.FixableNow)
	}

	cveID := extractRaw(assessment.Vulnerability.CVEID)
	pkg := extractRaw(assessment.Vulnerability.Package)
	fixVersion := extractRaw(assessment.Vulnerability.FixVersion)

	repoPath := opts.RepoPath
	if repoPath == "" {
		repoPath = assess.DeriveRepoURL(extractOperatorName(assessment))
		if repoPath == "" {
			repoPath = "."
		}
	}

	resolvedPath, cleanup, err := assess.ResolveRepoPath(repoPath)
	if err != nil {
		return nil, fmt.Errorf("resolving repo path: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	scanPath := resolvedPath
	operatorVersion := assessment.Source.AffectedOperatorVersion
	var worktreeCleanup func()

	if operatorVersion != "" {
		branch := goversion.ReleaseBranch(operatorVersion)
		if goversion.HasBranch(resolvedPath, branch) {
			wt, wtCleanup, err := goversion.CreateWorktree(resolvedPath, branch)
			if err == nil {
				scanPath = wt
				worktreeCleanup = wtCleanup
			}
		}
	}
	if worktreeCleanup != nil {
		defer worktreeCleanup()
	}

	module := extractModule(assessment)
	operatorName := extractOperatorName(assessment)

	strategies := buildStrategies(opts, module)
	if len(strategies) == 0 {
		return nil, fmt.Errorf("no applicable strategies for module %q with strategy %q", module, opts.Strategy)
	}

	stratOpts := StrategyOptions{
		RepoPath:        scanPath,
		Package:         pkg,
		Module:          module,
		FixVersion:      fixVersion,
		CVEID:           cveID,
		DryRun:          opts.DryRun,
		OperatorName:    operatorName,
		ImageName:       extractImageName(assessment),
		OperatorVersion: operatorVersion,
	}

	var lastErr error
	for _, strat := range strategies {
		backup, err := BackupGoFiles(scanPath)
		if err != nil {
			return nil, fmt.Errorf("backup before %s: %w", strat.Name(), err)
		}

		stratResult, err := strat.Apply(stratOpts)
		if err != nil {
			lastErr = fmt.Errorf("strategy %s: %w", strat.Name(), err)
			_ = backup.Restore()
			continue
		}

		if opts.DryRun {
			return &Result{
				TicketID:   opts.TicketID,
				CVEID:      cveID,
				Strategy:   strat.Name(),
				Risk:       strat.Risk(),
				Assessment: assessment,
				DryRun:     true,
				Validation: &ValidationResult{
					Steps: []StepResult{{Name: "dry-run", Passed: true, Output: stratResult.Command}},
				},
			}, nil
		}

		validation, err := Validate(scanPath, cveID, opts.RunTests)
		if err != nil {
			_ = backup.Restore()
			lastErr = fmt.Errorf("validation after %s: %w", strat.Name(), err)
			continue
		}

		if validation.Passed {
			result := &Result{
				TicketID:   opts.TicketID,
				CVEID:      cveID,
				Strategy:   strat.Name(),
				Risk:       strat.Risk(),
				Validation: validation,
				Assessment: assessment,
				DryRun:     false,
			}

			if opts.CreatePR {
				prOpts := pr.Options{
					RepoPath:   scanPath,
					CVEID:      cveID,
					Package:    pkg,
					FixVersion: fixVersion,
					Strategy:   string(strat.Name()),
					Risk:       strat.Risk(),
					TicketID:   opts.TicketID,
				}
				var steps []pr.ValidationStep
				for _, s := range validation.Steps {
					steps = append(steps, pr.ValidationStep{Name: s.Name, Passed: s.Passed})
				}
				prOpts.Description = pr.FormatDescriptionWithValidation(prOpts, steps)
				prResult, err := pr.Create(prOpts)
				if err != nil {
					return result, fmt.Errorf("fix succeeded but PR creation failed: %w", err)
				}
				result.PRURL = prResult.PRURL
			}

			return result, nil
		}

		_ = backup.Restore()
		lastErr = fmt.Errorf("strategy %s: validation failed (CVE removed: %v)", strat.Name(), validation.CVERemoved)
	}

	return &Result{
		TicketID:   opts.TicketID,
		CVEID:      cveID,
		Assessment: assessment,
		DryRun:     opts.DryRun,
	}, fmt.Errorf("all strategies exhausted: %w", lastErr)
}

func buildStrategies(opts Options, module string) []Strategy {
	if opts.Strategy != StrategyAuto && opts.Strategy != "" {
		switch opts.Strategy {
		case StrategyGoMinor:
			return []Strategy{&goMinorStrategy{}}
		case StrategyDirect:
			return []Strategy{&directStrategy{}}
		case StrategyTransitive:
			return []Strategy{&transitiveStrategy{}}
		case StrategyReplace:
			return []Strategy{&replaceStrategy{}}
		case StrategyMajor:
			return []Strategy{&majorStrategy{Approved: opts.ApproveMajor}}
		}
		return nil
	}

	var strategies []Strategy
	if module == "stdlib" {
		strategies = append(strategies, &goMinorStrategy{})
	}
	strategies = append(strategies,
		&directStrategy{},
		&transitiveStrategy{},
		&replaceStrategy{},
	)
	if opts.ApproveMajor {
		strategies = append(strategies, &majorStrategy{Approved: true})
	}
	return strategies
}

func extractRaw(s string) string {
	if i := strings.Index(s, " "); i > 0 {
		return s[:i]
	}
	return s
}

func extractModule(result *types.Result) string {
	if result == nil {
		return ""
	}
	pkg := extractRaw(result.Vulnerability.Package)
	if goversion.IsStdlibPackage(pkg) {
		return "stdlib"
	}
	return pkg
}

func extractOperatorName(result *types.Result) string {
	if result == nil {
		return ""
	}
	av := result.Source.AffectedOperatorVersion
	if i := strings.Index(av, " "); i > 0 {
		return av[:i]
	}
	return av
}

func extractImageName(result *types.Result) string {
	if result == nil || result.Analysis.ReleaseBranch == nil {
		return ""
	}
	return extractRaw(result.Analysis.ReleaseBranch.CatalogComponent)
}
