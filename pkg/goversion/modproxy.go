package goversion

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

var moduleProxyURL = "https://proxy.golang.org"

func FetchModuleGoVersion(modulePath, version string) (string, error) {
	if modulePath == "stdlib" {
		return version, nil
	}

	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	url := fmt.Sprintf("%s/%s/@v/%s.mod", moduleProxyURL, modulePath, version)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("fetching module go.mod: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("module proxy returned %d for %s@%s", resp.StatusCode, modulePath, version)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading module go.mod: %w", err)
	}

	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "go ") {
			return strings.TrimPrefix(line, "go "), nil
		}
	}

	return "", nil
}
