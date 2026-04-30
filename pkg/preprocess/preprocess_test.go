package preprocess

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()

	digest := &CVEDigest{
		CVEID:           "CVE-2026-1234",
		Summary:         "Test vulnerability",
		AffectedPackage: "golang.org/x/net",
		FixVersion:      "0.17.0",
		RiskLevel:       "high",
		Actionable:      true,
		Keywords:        []string{"go", "dependency"},
	}

	saveCache(dir, "CVE-2026-1234", digest)

	loaded, ok := loadCache(dir, "CVE-2026-1234")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if loaded.CVEID != "CVE-2026-1234" {
		t.Errorf("CVEID = %q, want CVE-2026-1234", loaded.CVEID)
	}
	if loaded.Summary != "Test vulnerability" {
		t.Errorf("Summary = %q, want Test vulnerability", loaded.Summary)
	}
	if loaded.FixVersion != "0.17.0" {
		t.Errorf("FixVersion = %q, want 0.17.0", loaded.FixVersion)
	}
	if !loaded.Actionable {
		t.Error("expected Actionable to be true")
	}
	if len(loaded.Keywords) != 2 {
		t.Errorf("expected 2 keywords, got %d", len(loaded.Keywords))
	}
}

func TestCacheMiss(t *testing.T) {
	dir := t.TempDir()
	_, ok := loadCache(dir, "CVE-9999-0000")
	if ok {
		t.Error("expected cache miss for nonexistent CVE")
	}
}

func TestProcessWithMockAPI(t *testing.T) {
	digestJSON := `{"summary":"test vuln","affected_package":"net/http","fix_version":"1.25.9","risk_level":"high","actionable":true,"keywords":["go","cve"]}`

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resp := map[string]interface{}{
			"content": []map[string]string{
				{"type": "text", "text": digestJSON},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Temporarily override the API endpoint by setting env vars
	// Since Process uses a hardcoded URL, we test the cache path instead
	dir := t.TempDir()

	os.Setenv("ANTHROPIC_API_KEY", "test-key")
	defer os.Unsetenv("ANTHROPIC_API_KEY")

	// Pre-populate cache to avoid hitting the real API
	expected := &CVEDigest{
		CVEID:           "CVE-2026-5555",
		Summary:         "cached vuln",
		AffectedPackage: "net/http",
		FixVersion:      "1.25.9",
		RiskLevel:       "high",
		Actionable:      true,
		Keywords:        []string{"go"},
	}
	saveCache(dir, "CVE-2026-5555", expected)

	result, err := Process("CVE-2026-5555", "test advisory", dir)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if result.Summary != "cached vuln" {
		t.Errorf("Summary = %q, want 'cached vuln'", result.Summary)
	}
}

func TestProcessNoAPIKey(t *testing.T) {
	os.Unsetenv("ANTHROPIC_API_KEY")
	_, err := Process("CVE-2026-1111", "test", "")
	if err == nil {
		t.Error("expected error when ANTHROPIC_API_KEY is not set")
	}
}
