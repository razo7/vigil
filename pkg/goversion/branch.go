package goversion

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func ReleaseBranch(operatorVersion string) string {
	v := strings.TrimPrefix(operatorVersion, "v")
	parts := strings.Split(v, ".")
	if len(parts) >= 2 {
		return fmt.Sprintf("release-%s.%s", parts[0], parts[1])
	}
	return fmt.Sprintf("release-%s", v)
}

func HasBranch(repoPath, branch string) bool {
	cmd := exec.Command("git", "rev-parse", "--verify", branch)
	cmd.Dir = repoPath
	if err := cmd.Run(); err == nil {
		return true
	}

	cmd = exec.Command("git", "rev-parse", "--verify", "upstream/"+branch)
	cmd.Dir = repoPath
	if err := cmd.Run(); err == nil {
		return true
	}

	cmd = exec.Command("git", "rev-parse", "--verify", "origin/"+branch)
	cmd.Dir = repoPath
	return cmd.Run() == nil
}

func CreateWorktree(repoPath, branch string) (worktreePath string, cleanup func(), err error) {
	tmpDir, err := os.MkdirTemp("", "vigil-worktree-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp dir: %w", err)
	}

	worktreePath = filepath.Join(tmpDir, "repo")

	ref := branch
	for _, remote := range []string{"upstream", "origin"} {
		cmd := exec.Command("git", "rev-parse", "--verify", remote+"/"+branch)
		cmd.Dir = repoPath
		if cmd.Run() == nil {
			ref = remote + "/" + branch
			break
		}
	}

	cmd := exec.Command("git", "worktree", "add", "--detach", worktreePath, ref)
	cmd.Dir = repoPath
	out, err := cmd.CombinedOutput()
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("creating worktree for %s: %s: %w", branch, string(out), err)
	}

	cleanup = func() {
		exec.Command("git", "worktree", "remove", "--force", worktreePath).Run()
		os.RemoveAll(tmpDir)
	}

	return worktreePath, cleanup, nil
}
