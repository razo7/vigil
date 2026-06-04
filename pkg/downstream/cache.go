package downstream

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type CacheEntry struct {
	Operator  string    `json:"operator"`
	Version   string    `json:"version"`
	GoVersion string    `json:"go_version"`
	Branch    string    `json:"branch"`
	FetchedAt time.Time `json:"fetched_at"`
}

type Cache struct {
	Entries []CacheEntry `json:"entries"`
}

var cacheDir = resolveCacheDir()
const cacheFileName = "downstream-go-cache.json"

func resolveCacheDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".vigil")
	}
	return ".vigil"
}
const maxAge = 7 * 24 * time.Hour

func cacheFilePath() string {
	return filepath.Join(cacheDir, cacheFileName)
}

func LoadCache() (*Cache, error) {
	data, err := os.ReadFile(cacheFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return &Cache{}, nil
		}
		return nil, fmt.Errorf("reading cache file: %w", err)
	}

	var cache Cache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, fmt.Errorf("parsing cache file: %w", err)
	}
	return &cache, nil
}

func (c *Cache) Save() error {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling cache: %w", err)
	}

	if err := os.WriteFile(cacheFilePath(), data, 0o644); err != nil {
		return fmt.Errorf("writing cache file: %w", err)
	}
	return nil
}

func (c *Cache) Get(operator, version string) (entry CacheEntry, found bool) {
	for _, e := range c.Entries {
		if e.Operator == operator && e.Version == version {
			return e, true
		}
	}
	return CacheEntry{}, false
}

func (c *Cache) IsStale(entry CacheEntry) bool {
	return time.Since(entry.FetchedAt) > maxAge
}

func (c *Cache) Set(operator, version, goVersion, branch string) {
	for i, e := range c.Entries {
		if e.Operator == operator && e.Version == version {
			c.Entries[i].GoVersion = goVersion
			c.Entries[i].Branch = branch
			c.Entries[i].FetchedAt = time.Now().UTC()
			return
		}
	}
	c.Entries = append(c.Entries, CacheEntry{
		Operator:  operator,
		Version:   version,
		GoVersion: goVersion,
		Branch:    branch,
		FetchedAt: time.Now().UTC(),
	})
}
