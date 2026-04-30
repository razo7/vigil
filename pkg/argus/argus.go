package argus

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultGitLabHost = "https://gitlab.cee.redhat.com"
	projectPath       = "product-security/prodsec-skills"
	defaultRef        = "main"
	cacheTTL          = 24 * time.Hour
)

type Skill struct {
	Name    string
	Path    string
	Content string
	Tags    []string
}

var skills = []Skill{
	{
		Name: "vulnerability-management",
		Path: "skills/secure_development/supply-chain/vulnerability-management.md",
		Tags: []string{"cve", "triage", "timeline", "response"},
	},
	{
		Name: "go-security",
		Path: "skills/secure_development/languages/go-security.md",
		Tags: []string{"go", "golang", "govulncheck", "dependency"},
	},
	{
		Name: "operator-security",
		Path: "skills/secure_development/kubernetes/operator-security.md",
		Tags: []string{"kubernetes", "operator", "rbac", "container"},
	},
	{
		Name: "differential-review",
		Path: "skills/security_auditing/audit-workflow/differential-review.md",
		Tags: []string{"review", "diff", "patch", "pr"},
	},
	{
		Name: "supply-chain-risk-auditor",
		Path: "skills/secure_development/supply-chain/supply-chain-risk-auditor.md",
		Tags: []string{"dependency", "supply-chain", "risk", "maintainer"},
	},
	{
		Name: "container-hardening",
		Path: "skills/secure_development/kubernetes/container-hardening.md",
		Tags: []string{"container", "hardening", "image", "dockerfile"},
	},
}

func FetchSkill(name, cacheDir string) (*Skill, error) {
	for _, s := range skills {
		if s.Name == name {
			return fetchAndCache(s, cacheDir)
		}
	}
	return nil, fmt.Errorf("unknown skill %q", name)
}

func FetchSkills(names []string, cacheDir string) ([]Skill, error) {
	var result []Skill
	for _, name := range names {
		s, err := FetchSkill(name, cacheDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: cannot fetch skill %q: %v\n", name, err)
			continue
		}
		result = append(result, *s)
	}
	return result, nil
}

func MatchSkills(keywords []string) []string {
	keySet := make(map[string]bool)
	for _, k := range keywords {
		keySet[strings.ToLower(k)] = true
	}

	seen := make(map[string]bool)
	var matched []string
	for _, s := range skills {
		for _, tag := range s.Tags {
			if keySet[tag] && !seen[s.Name] {
				matched = append(matched, s.Name)
				seen[s.Name] = true
				break
			}
		}
	}
	return matched
}

func AvailableSkills() []string {
	names := make([]string, len(skills))
	for i, s := range skills {
		names[i] = s.Name
	}
	return names
}

func fetchAndCache(s Skill, cacheDir string) (*Skill, error) {
	if cacheDir != "" {
		if content, ok := readCache(cacheDir, s.Name); ok {
			s.Content = content
			return &s, nil
		}
	}

	token := os.Getenv("GITLAB_TOKEN")
	if token == "" {
		token = os.Getenv("GITLAB_PRIVATE_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("GITLAB_TOKEN or GITLAB_PRIVATE_TOKEN required to fetch ARGUS skills")
	}

	host := os.Getenv("GITLAB_HOST")
	if host == "" {
		host = defaultGitLabHost
	}

	encodedProject := url.PathEscape(projectPath)
	encodedFile := url.PathEscape(s.Path)
	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/repository/files/%s/raw?ref=%s",
		host, encodedProject, encodedFile, defaultRef)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching skill %s: %w", s.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitLab returned %d for skill %s", resp.StatusCode, s.Name)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading skill %s: %w", s.Name, err)
	}

	s.Content = string(body)

	if cacheDir != "" {
		writeCache(cacheDir, s.Name, s.Content)
	}

	return &s, nil
}

func cacheKey(name string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(name)))[:16] + ".md"
}

func readCache(cacheDir, name string) (string, bool) {
	path := filepath.Join(cacheDir, "argus-skills", cacheKey(name))
	info, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	if time.Since(info.ModTime()) > cacheTTL {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(data), true
}

func writeCache(cacheDir, name, content string) {
	dir := filepath.Join(cacheDir, "argus-skills")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	path := filepath.Join(dir, cacheKey(name))
	os.WriteFile(path, []byte(content), 0644)
}
