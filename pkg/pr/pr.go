package pr

import (
	"fmt"
	"os/exec"
	"strings"
)

type Options struct {
	RepoPath    string
	CVEID       string
	Package     string
	FixVersion  string
	Strategy    string
	Risk        int
	TicketID    string
	Description string
}

type Result struct {
	BranchName string `json:"branch_name"`
	PRURL      string `json:"pr_url"`
}

func Create(opts Options) (*Result, error) {
	branchName := fmt.Sprintf("fix/%s", opts.CVEID)

	if err := gitRun(opts.RepoPath, "checkout", "-b", branchName); err != nil {
		return nil, fmt.Errorf("creating branch %s: %w", branchName, err)
	}

	if err := gitRun(opts.RepoPath, "add", "go.mod", "go.sum"); err != nil {
		return nil, fmt.Errorf("staging files: %w", err)
	}

	vendorCheck := exec.Command("git", "status", "--porcelain", "vendor/")
	vendorCheck.Dir = opts.RepoPath
	if out, _ := vendorCheck.Output(); len(out) > 0 {
		if err := gitRun(opts.RepoPath, "add", "vendor/"); err != nil {
			return nil, fmt.Errorf("staging vendor: %w", err)
		}
	}

	commitMsg := fmt.Sprintf("Bump %s to %s\n\nCo-Authored-By: vigil <noreply@vigil.local>",
		opts.Package, opts.FixVersion)
	if err := gitRun(opts.RepoPath, "commit", "-S", "-m", commitMsg); err != nil {
		return nil, fmt.Errorf("committing: %w", err)
	}

	if err := gitRun(opts.RepoPath, "push", "-u", "origin", branchName); err != nil {
		return nil, fmt.Errorf("pushing: %w", err)
	}

	prURL, err := createGHPR(opts)
	if err != nil {
		return nil, fmt.Errorf("creating PR: %w", err)
	}

	return &Result{
		BranchName: branchName,
		PRURL:      prURL,
	}, nil
}

func createGHPR(opts Options) (string, error) {
	title := fmt.Sprintf("Bump %s to %s", opts.Package, opts.FixVersion)
	if len(title) > 70 {
		title = title[:67] + "..."
	}

	body := opts.Description
	if body == "" {
		body = FormatDescription(opts)
	}

	cmd := exec.Command("gh", "pr", "create",
		"--draft",
		"--title", title,
		"--body", body,
	)
	cmd.Dir = opts.RepoPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gh pr create: %s: %w", string(output), err)
	}

	prURL := strings.TrimSpace(string(output))
	return prURL, nil
}

func gitRun(repoPath string, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = repoPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %s: %s: %w", strings.Join(args, " "), string(output), err)
	}
	return nil
}
