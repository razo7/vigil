package downstream

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const defaultGitLabHost = "https://gitlab.cee.redhat.com"

var goVersionRe = regexp.MustCompile(`golang[-\w]*[:\-]v?(\d+\.\d+(?:\.\d+)?)`)

type ContainerfileInfo struct {
	GoVersion     string
	GoVersionLine int
	Branch        string
	FilePath      string
	ImageName     string
}

var operatorShortNames = map[string]string{
	"fence-agents-remediation":     "far",
	"self-node-remediation":        "snr",
	"node-healthcheck-controller":  "nhc",
	"node-maintenance-operator":    "nmo",
	"machine-deletion-remediation": "mdr",
}

func downstreamBranches(operatorName, operatorVersion string) []string {
	if operatorVersion == "" {
		return []string{"main"}
	}
	short, ok := operatorShortNames[operatorName]
	if !ok {
		return []string{"main"}
	}
	ver := strings.ReplaceAll(operatorVersion, ".", "-")
	return []string{
		fmt.Sprintf("%s-%s", short, ver),                            // e.g., "far-0-8"
		fmt.Sprintf("rhwa-%s-%s-rhel-8", short, operatorVersion),    // e.g., "rhwa-far-0.4-rhel-8"
		fmt.Sprintf("rhwa-%s-%s-rhel-9", short, operatorVersion),    // e.g., "rhwa-far-0.8-rhel-9"
	}
}

func FetchGoVersion(operatorName, imageName, branch string) (*ContainerfileInfo, error) {
	token := os.Getenv("GITLAB_TOKEN")
	if token == "" {
		token = os.Getenv("GITLAB_PRIVATE_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("GITLAB_TOKEN or GITLAB_PRIVATE_TOKEN environment variable is required for downstream Containerfile access")
	}

	host := os.Getenv("GITLAB_HOST")
	if host == "" {
		host = defaultGitLabHost
	}

	projectPath := fmt.Sprintf("dragonfly/%s", operatorName)

	ref := branch
	if ref == "" {
		ref = "main"
	}

	candidates := []string{
		fmt.Sprintf("Containerfile.%s", operatorName),
		fmt.Sprintf("distgit/containers/%s-operator/Dockerfile.in", operatorName),
	}

	var lastErr error
	for _, filePath := range candidates {
		content, err := fetchFileFromGitLab(host, token, projectPath, filePath, ref)
		if err != nil {
			lastErr = err
			continue
		}

		goVersion, goLine := extractGoVersion(content)
		return &ContainerfileInfo{
			GoVersion:     goVersion,
			GoVersionLine: goLine,
			Branch:        ref,
			FilePath:      filePath,
			ImageName:     imageName,
		}, nil
	}

	return nil, fmt.Errorf("no Containerfile found for %s@%s (tried %d paths): %w",
		operatorName, ref, len(candidates), lastErr)
}

// FetchGoVersionForOperator derives the downstream branch from operator version
// and fetches the Go version from the Containerfile, trying multiple branch
// naming conventions (e.g., far-0-8, rhwa-far-0.4-rhel-8).
func FetchGoVersionForOperator(operatorName, imageName, operatorVersion string) (*ContainerfileInfo, error) {
	branches := downstreamBranches(operatorName, operatorVersion)
	var lastErr error
	for _, branch := range branches {
		info, err := FetchGoVersion(operatorName, imageName, branch)
		if err == nil {
			return info, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("tried branches %v: %w", branches, lastErr)
}

func fetchFileFromGitLab(host, token, projectPath, filePath, ref string) (string, error) {
	encodedProject := url.PathEscape(projectPath)
	encodedFile := url.PathEscape(filePath)

	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/repository/files/%s/raw?ref=%s",
		host, encodedProject, encodedFile, url.QueryEscape(ref))

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating GitLab request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching from GitLab: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitLab API returned %d for %s/%s@%s", resp.StatusCode, projectPath, filePath, ref)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading GitLab response: %w", err)
	}

	return string(body), nil
}

func extractGoVersion(containerfileContent string) (string, int) {
	lines := strings.Split(containerfileContent, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(trimmed), "FROM") {
			continue
		}
		if m := goVersionRe.FindStringSubmatch(trimmed); len(m) == 2 {
			return m[1], i + 1
		}
	}

	for i, line := range lines {
		if m := goVersionRe.FindStringSubmatch(line); len(m) == 2 {
			return m[1], i + 1
		}
	}

	return "", 0
}
