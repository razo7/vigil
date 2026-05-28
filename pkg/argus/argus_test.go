package argus

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMatchSkills(t *testing.T) {
	tests := []struct {
		name     string
		keywords []string
		want     []string
	}{
		{
			name:     "go keyword",
			keywords: []string{"go"},
			want:     []string{"go-security"},
		},
		{
			name:     "cve and dependency",
			keywords: []string{"cve", "dependency"},
			want:     []string{"vulnerability-management", "go-security", "supply-chain-risk-auditor"},
		},
		{
			name:     "container",
			keywords: []string{"container"},
			want:     []string{"operator-security", "container-hardening"},
		},
		{
			name:     "no match",
			keywords: []string{"python", "javascript"},
			want:     nil,
		},
		{
			name:     "empty",
			keywords: nil,
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchSkills(tt.keywords)
			if len(got) != len(tt.want) {
				t.Errorf("MatchSkills(%v) returned %d skills, want %d: %v", tt.keywords, len(got), len(tt.want), got)
				return
			}
			for i, name := range tt.want {
				if got[i] != name {
					t.Errorf("skill[%d] = %q, want %q", i, got[i], name)
				}
			}
		})
	}
}

func TestAvailableSkills(t *testing.T) {
	names := AvailableSkills()
	if len(names) != 6 {
		t.Errorf("expected 6 skills, got %d", len(names))
	}
	if names[0] != "vulnerability-management" {
		t.Errorf("first skill = %q, want vulnerability-management", names[0])
	}
}

func TestFetchSkillWithCache(t *testing.T) {
	cacheDir := t.TempDir()
	skillDir := filepath.Join(cacheDir, "argus-skills")
	os.MkdirAll(skillDir, 0755)

	key := cacheKey("go-security")
	os.WriteFile(filepath.Join(skillDir, key), []byte("# Go Security Skill\nCached content"), 0644)

	skill, err := FetchSkill("go-security", cacheDir)
	if err != nil {
		t.Fatalf("FetchSkill with cache failed: %v", err)
	}
	if skill.Content != "# Go Security Skill\nCached content" {
		t.Errorf("unexpected content: %q", skill.Content)
	}
	if skill.Name != "go-security" {
		t.Errorf("Name = %q, want go-security", skill.Name)
	}
}

func TestFetchSkillUnknown(t *testing.T) {
	_, err := FetchSkill("nonexistent-skill", "")
	if err == nil {
		t.Error("expected error for unknown skill")
	}
}

func TestFetchSkillFromGitHub(t *testing.T) {
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# GitHub Skill Content"))
	}))
	defer ghServer.Close()

	t.Setenv("GITHUB_RAW_BASE", ghServer.URL)
	t.Setenv("GITLAB_HOST", "http://unreachable.invalid")

	cacheDir := t.TempDir()
	skill, err := FetchSkill("go-security", cacheDir)
	if err != nil {
		t.Fatalf("FetchSkill from mock GitHub failed: %v", err)
	}
	if skill.Content != "# GitHub Skill Content" {
		t.Errorf("unexpected content: %q", skill.Content)
	}

	cached, ok := readCache(cacheDir, "go-security")
	if !ok {
		t.Error("expected skill to be cached after fetch")
	}
	if cached != "# GitHub Skill Content" {
		t.Errorf("cached content = %q, want fetched content", cached)
	}
}

func TestFetchSkillFallbackToGitLab(t *testing.T) {
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ghServer.Close()

	glServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte("# GitLab Skill Content"))
	}))
	defer glServer.Close()

	t.Setenv("GITHUB_RAW_BASE", ghServer.URL)
	t.Setenv("GITLAB_TOKEN", "test-token")
	t.Setenv("GITLAB_HOST", glServer.URL)

	cacheDir := t.TempDir()
	skill, err := FetchSkill("go-security", cacheDir)
	if err != nil {
		t.Fatalf("FetchSkill fallback to mock GitLab failed: %v", err)
	}
	if skill.Content != "# GitLab Skill Content" {
		t.Errorf("unexpected content: %q", skill.Content)
	}

	cached, ok := readCache(cacheDir, "go-security")
	if !ok {
		t.Error("expected skill to be cached after fetch")
	}
	if cached != "# GitLab Skill Content" {
		t.Errorf("cached content = %q, want fetched content", cached)
	}
}

func TestFetchSkillBothSourcesFail(t *testing.T) {
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ghServer.Close()

	glServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer glServer.Close()

	t.Setenv("GITHUB_RAW_BASE", ghServer.URL)
	t.Setenv("GITLAB_TOKEN", "test-token")
	t.Setenv("GITLAB_HOST", glServer.URL)

	_, err := FetchSkill("go-security", "")
	if err == nil {
		t.Error("expected error when both sources fail")
	}
}

func TestCacheExpiry(t *testing.T) {
	cacheDir := t.TempDir()
	writeCache(cacheDir, "test-skill", "old content")

	path := filepath.Join(cacheDir, "argus-skills", cacheKey("test-skill"))
	old := time.Now().Add(-48 * time.Hour)
	os.Chtimes(path, old, old)

	_, ok := readCache(cacheDir, "test-skill")
	if ok {
		t.Error("expected expired cache to miss")
	}
}
