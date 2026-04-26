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

var goVersionRe = regexp.MustCompile(`golang[:\-](\d+\.\d+(?:\.\d+)?)`)

type ContainerfileInfo struct {
	GoVersion string
	Branch    string
	ImageName string
}

func FetchGoVersion(operatorName, imageName, branch string) (*ContainerfileInfo, error) {
	token := os.Getenv("GITLAB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITLAB_TOKEN environment variable is required for downstream Containerfile access")
	}

	host := os.Getenv("GITLAB_HOST")
	if host == "" {
		host = defaultGitLabHost
	}

	projectPath := fmt.Sprintf("dragonfly/%s", operatorName)
	filePath := fmt.Sprintf("Containerfile.%s", imageName)
	if imageName == "" {
		filePath = "Containerfile"
	}

	ref := branch
	if ref == "" {
		ref = "main"
	}

	content, err := fetchFileFromGitLab(host, token, projectPath, filePath, ref)
	if err != nil {
		return nil, err
	}

	goVersion := extractGoVersion(content)

	return &ContainerfileInfo{
		GoVersion: goVersion,
		Branch:    ref,
		ImageName: imageName,
	}, nil
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

func extractGoVersion(containerfileContent string) string {
	for _, line := range strings.Split(containerfileContent, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(line), "FROM") {
			continue
		}
		if m := goVersionRe.FindStringSubmatch(line); len(m) == 2 {
			return m[1]
		}
	}

	if m := goVersionRe.FindStringSubmatch(containerfileContent); len(m) == 2 {
		return m[1]
	}

	return ""
}
