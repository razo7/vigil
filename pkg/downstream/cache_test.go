package downstream

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCacheSaveAndLoad(t *testing.T) {
	setupTestCacheDir(t)

	cache := &Cache{}
	cache.Set("fence-agents-remediation", "0.8", "1.25.3", "far-0-8")

	if err := cache.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := LoadCache()
	if err != nil {
		t.Fatalf("LoadCache() error: %v", err)
	}

	if len(loaded.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(loaded.Entries))
	}

	entry := loaded.Entries[0]
	if entry.Operator != "fence-agents-remediation" {
		t.Errorf("Operator = %q, want %q", entry.Operator, "fence-agents-remediation")
	}
	if entry.GoVersion != "1.25.3" {
		t.Errorf("GoVersion = %q, want %q", entry.GoVersion, "1.25.3")
	}
	if entry.Branch != "far-0-8" {
		t.Errorf("Branch = %q, want %q", entry.Branch, "far-0-8")
	}
}

func TestCacheGetExisting(t *testing.T) {
	cache := &Cache{}
	cache.Set("fence-agents-remediation", "0.8", "1.25.3", "far-0-8")
	cache.Set("self-node-remediation", "0.10", "1.25.8", "snr-0-10")

	entry, found := cache.Get("self-node-remediation", "0.10")
	if !found {
		t.Fatal("expected to find entry")
	}
	if entry.GoVersion != "1.25.8" {
		t.Errorf("GoVersion = %q, want %q", entry.GoVersion, "1.25.8")
	}
}

func TestCacheGetMissing(t *testing.T) {
	cache := &Cache{}
	cache.Set("fence-agents-remediation", "0.8", "1.25.3", "far-0-8")

	_, found := cache.Get("unknown-operator", "1.0")
	if found {
		t.Error("expected not found for missing entry")
	}
}

func TestCacheStaleEntry(t *testing.T) {
	cache := &Cache{}
	cache.Entries = append(cache.Entries, CacheEntry{
		Operator:  "fence-agents-remediation",
		Version:   "0.8",
		GoVersion: "1.25.3",
		Branch:    "far-0-8",
		FetchedAt: time.Now().Add(-8 * 24 * time.Hour),
	})

	entry, found := cache.Get("fence-agents-remediation", "0.8")
	if !found {
		t.Fatal("expected to find entry")
	}
	if !cache.IsStale(entry) {
		t.Error("expected entry to be stale (8 days old)")
	}
}

func TestCacheFreshEntry(t *testing.T) {
	cache := &Cache{}
	cache.Set("fence-agents-remediation", "0.8", "1.25.3", "far-0-8")

	entry, found := cache.Get("fence-agents-remediation", "0.8")
	if !found {
		t.Fatal("expected to find entry")
	}
	if cache.IsStale(entry) {
		t.Error("expected entry to be fresh")
	}
}

func TestCacheSetOverwrites(t *testing.T) {
	cache := &Cache{}
	cache.Set("fence-agents-remediation", "0.8", "1.25.3", "far-0-8")
	cache.Set("fence-agents-remediation", "0.8", "1.25.9", "far-0-8")

	if len(cache.Entries) != 1 {
		t.Fatalf("expected 1 entry after overwrite, got %d", len(cache.Entries))
	}

	entry, found := cache.Get("fence-agents-remediation", "0.8")
	if !found {
		t.Fatal("expected to find entry")
	}
	if entry.GoVersion != "1.25.9" {
		t.Errorf("GoVersion = %q, want %q after overwrite", entry.GoVersion, "1.25.9")
	}
}

func TestLoadCacheMissingFile(t *testing.T) {
	setupTestCacheDir(t)

	cache, err := LoadCache()
	if err != nil {
		t.Fatalf("LoadCache() on missing file should return empty cache, got error: %v", err)
	}
	if len(cache.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(cache.Entries))
	}
}

func setupTestCacheDir(t *testing.T) {
	t.Helper()

	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Chdir(origDir)
	})

	if err := os.MkdirAll(filepath.Join(tmpDir, cacheDir), 0o755); err != nil {
		t.Fatal(err)
	}
}
