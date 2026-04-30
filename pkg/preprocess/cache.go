package preprocess

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

func cacheFile(cacheDir, cveID string) string {
	safe := strings.ReplaceAll(cveID, "/", "_")
	return filepath.Join(cacheDir, "cve-preprocessed", safe+".json")
}

func loadCache(cacheDir, cveID string) (*CVEDigest, bool) {
	data, err := os.ReadFile(cacheFile(cacheDir, cveID))
	if err != nil {
		return nil, false
	}
	var digest CVEDigest
	if err := json.Unmarshal(data, &digest); err != nil {
		return nil, false
	}
	return &digest, true
}

func saveCache(cacheDir, cveID string, digest *CVEDigest) {
	path := cacheFile(cacheDir, cveID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return
	}
	data, err := json.MarshalIndent(digest, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(path, data, 0644)
}
