package assess

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func isGitURL(path string) bool {
	if strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "git@") {
		return true
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "ssh://") {
		return true
	}
	return false
}

func resolveRepoPath(path string) (repoPath string, cleanup func(), err error) {
	if !isGitURL(path) {
		return path, nil, nil
	}

	tmpDir, err := os.MkdirTemp("", "vigil-clone-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp dir: %w", err)
	}

	cmd := exec.Command("git", "clone", path, tmpDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("cloning %s: %s: %w", path, string(out), err)
	}

	cleanup = func() {
		os.RemoveAll(tmpDir)
	}

	return tmpDir, cleanup, nil
}
