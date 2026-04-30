package preprocess

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

const defaultModel = "claude-sonnet-4-6-20250514"

type CVEDigest struct {
	CVEID           string   `json:"cve_id"`
	Summary         string   `json:"summary"`
	AffectedPackage string   `json:"affected_package"`
	FixVersion      string   `json:"fix_version"`
	RiskLevel       string   `json:"risk_level"`
	Actionable      bool     `json:"actionable"`
	Keywords        []string `json:"keywords"`
}

func Process(cveID, advisory string, cacheDir string) (*CVEDigest, error) {
	if cacheDir != "" {
		if cached, ok := loadCache(cacheDir, cveID); ok {
			return cached, nil
		}
	}

	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY required for CVE preprocessing")
	}

	prompt := fmt.Sprintf(`Analyze this CVE advisory and return a JSON object with these fields:
- summary: one-sentence description of the vulnerability
- affected_package: the Go package or module affected
- fix_version: the version that fixes this CVE (or "unknown")
- risk_level: one of "critical", "high", "medium", "low"
- actionable: true if there's a clear fix available, false otherwise
- keywords: list of relevant keywords for skill matching (e.g., "go", "container", "dependency", "cve")

CVE ID: %s
Advisory text:
%s

Return ONLY the JSON object, no markdown or explanation.`, cveID, advisory)

	reqBody := map[string]interface{}{
		"model":      defaultModel,
		"max_tokens": 512,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling Claude API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Claude API returned %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	var apiResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("parsing API response: %w", err)
	}

	if len(apiResp.Content) == 0 {
		return nil, fmt.Errorf("empty response from Claude API")
	}

	digest := &CVEDigest{CVEID: cveID}
	text := apiResp.Content[0].Text
	if err := json.Unmarshal([]byte(text), digest); err != nil {
		return nil, fmt.Errorf("parsing digest JSON: %w", err)
	}
	digest.CVEID = cveID

	if cacheDir != "" {
		saveCache(cacheDir, cveID, digest)
	}

	return digest, nil
}
