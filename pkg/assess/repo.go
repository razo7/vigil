package assess

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func IsGitURL(path string) bool {
	if strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "git@") {
		return true
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "ssh://") {
		return true
	}
	return false
}

func ResolveRepoPath(path string) (repoPath string, cleanup func(), err error) {
	if !IsGitURL(path) {
		return path, nil, nil
	}

	tmpDir, err := os.MkdirTemp("", "vigil-clone-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp dir: %w", err)
	}

	cmd := exec.Command("git", "clone", path, tmpDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		os.RemoveAll(tmpDir)
		tmpDir, err = os.MkdirTemp("", "vigil-clone-*")
		if err != nil {
			return "", nil, fmt.Errorf("creating temp dir for retry: %w", err)
		}
		cmd2 := exec.Command("git", "-c", "http.version=HTTP/1.1", "clone", path, tmpDir)
		if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
			os.RemoveAll(tmpDir)
			return "", nil, fmt.Errorf("cloning %s: %s (retry: %s): %w", path, string(out), string(out2), err2)
		}
	}

	cleanup = func() {
		os.RemoveAll(tmpDir)
	}

	return tmpDir, cleanup, nil
}
