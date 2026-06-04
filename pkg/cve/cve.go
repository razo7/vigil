package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type CVEInfo struct {
	Score          float64
	Severity       string
	Description    string
	CWE            string
	CWEDescription string
	References     []string
	Published      string
	CVEID          string
}

func FetchCVSSScore(cveID string) (*CVEInfo, error) {
	url := fmt.Sprintf("https://cveawg.mitre.org/api/cve/%s", cveID)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching CVE %s: %w", cveID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CVE API returned %d for %s", resp.StatusCode, cveID)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading CVE response: %w", err)
	}

	return parseCVEResponse(body)
}

func parseCVEResponse(data []byte) (*CVEInfo, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing CVE JSON: %w", err)
	}

	containers, _ := raw["containers"].(map[string]interface{})
	if containers == nil {
		return &CVEInfo{}, nil
	}

	result := &CVEInfo{}

	if meta, _ := raw["cveMetadata"].(map[string]interface{}); meta != nil {
		if pub, _ := meta["datePublished"].(string); pub != "" && len(pub) >= 10 {
			result.Published = pub[:10]
		}
	}

	if cna, _ := containers["cna"].(map[string]interface{}); cna != nil {
		if descs, _ := cna["descriptions"].([]interface{}); len(descs) > 0 {
			if d, _ := descs[0].(map[string]interface{}); d != nil {
				result.Description, _ = d["value"].(string)
			}
		}

		if problemTypes, _ := cna["problemTypes"].([]interface{}); len(problemTypes) > 0 {
			for _, pt := range problemTypes {
				ptMap, _ := pt.(map[string]interface{})
				if ptMap == nil {
					continue
				}
				if descriptions, _ := ptMap["descriptions"].([]interface{}); len(descriptions) > 0 {
					for _, desc := range descriptions {
						descMap, _ := desc.(map[string]interface{})
						if descMap == nil {
							continue
						}
						if cweID, _ := descMap["cweId"].(string); cweID != "" {
							result.CWE = cweID
							if cweDesc, _ := descMap["description"].(string); cweDesc != "" {
								result.CWEDescription = cweDesc
							}
							break
						}
					}
				}
				if result.CWE != "" {
					break
				}
			}
		}

		if refs, _ := cna["references"].([]interface{}); len(refs) > 0 {
			for _, ref := range refs {
				refMap, _ := ref.(map[string]interface{})
				if refMap == nil {
					continue
				}
				if u, _ := refMap["url"].(string); u != "" {
					result.References = append(result.References, u)
				}
			}
		}
	}

	if info := extractCVSSFromCNA(containers); info != nil {
		result.Score = info.Score
		result.Severity = info.Severity
		return result, nil
	}

	if info := extractCVSSFromADP(containers); info != nil {
		result.Score = info.Score
		result.Severity = info.Severity
		return result, nil
	}

	return result, nil
}

func extractCVSSFromCNA(containers map[string]interface{}) *CVEInfo {
	cna, _ := containers["cna"].(map[string]interface{})
	if cna == nil {
		return nil
	}
	metrics, _ := cna["metrics"].([]interface{})
	return extractFromMetrics(metrics)
}

func extractCVSSFromADP(containers map[string]interface{}) *CVEInfo {
	adpList, _ := containers["adp"].([]interface{})
	for _, adp := range adpList {
		adpMap, _ := adp.(map[string]interface{})
		if adpMap == nil {
			continue
		}
		metrics, _ := adpMap["metrics"].([]interface{})
		if info := extractFromMetrics(metrics); info != nil {
			return info
		}
	}
	return nil
}

func FetchGHSA(ghsaID string) (*CVEInfo, error) {
	url := fmt.Sprintf("https://api.github.com/advisories/%s", ghsaID)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d for %s", resp.StatusCode, ghsaID)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	info := &CVEInfo{}
	if cvss, _ := raw["cvss"].(map[string]interface{}); cvss != nil {
		if score, ok := cvss["score"].(float64); ok {
			info.Score = score
		}
	}
	if sev, _ := raw["severity"].(string); sev != "" {
		info.Severity = strings.ToUpper(sev)
	}
	if cveID, _ := raw["cve_id"].(string); cveID != "" {
		info.CVEID = cveID
	}
	if pub, _ := raw["published_at"].(string); pub != "" && len(pub) >= 10 {
		info.Published = pub[:10]
	}
	if desc, _ := raw["summary"].(string); desc != "" {
		info.Description = desc
	}
	return info, nil
}

func FetchWithFallback(id string) (*CVEInfo, error) {
	if strings.HasPrefix(id, "CVE-") {
		info, err := FetchCVSSScore(id)
		if err == nil && info != nil && info.Score > 0 {
			return info, nil
		}
		ghsa, ghsaErr := fetchGHSAByCVE(id)
		if ghsaErr == nil && ghsa != nil && (ghsa.Score > 0 || ghsa.Severity != "") {
			if info != nil {
				if ghsa.Score > 0 {
					info.Score = ghsa.Score
				}
				if ghsa.Severity != "" && info.Severity == "" {
					info.Severity = ghsa.Severity
				}
				if ghsa.Published != "" && info.Published == "" {
					info.Published = ghsa.Published
				}
				return info, nil
			}
			return ghsa, nil
		}
		return info, err
	}
	if strings.HasPrefix(id, "GHSA-") {
		return FetchGHSA(id)
	}
	return nil, fmt.Errorf("unknown ID format: %s", id)
}

func fetchGHSAByCVE(cveID string) (*CVEInfo, error) {
	url := fmt.Sprintf("https://api.github.com/advisories?cve_id=%s", cveID)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var advisories []map[string]interface{}
	if err := json.Unmarshal(body, &advisories); err != nil {
		return nil, err
	}
	if len(advisories) == 0 {
		return nil, nil
	}
	a := advisories[0]
	info := &CVEInfo{}
	if cvss, _ := a["cvss"].(map[string]interface{}); cvss != nil {
		if score, ok := cvss["score"].(float64); ok {
			info.Score = score
		}
	}
	if sev, _ := a["severity"].(string); sev != "" {
		info.Severity = strings.ToUpper(sev)
	}
	if pub, _ := a["published_at"].(string); pub != "" && len(pub) >= 10 {
		info.Published = pub[:10]
	}
	return info, nil
}

func extractFromMetrics(metrics []interface{}) *CVEInfo {
	for _, m := range metrics {
		metric, _ := m.(map[string]interface{})
		if metric == nil {
			continue
		}

		for key, val := range metric {
			if !strings.HasPrefix(key, "cvss") {
				continue
			}
			cvss, _ := val.(map[string]interface{})
			if cvss == nil {
				continue
			}

			info := &CVEInfo{}
			if score, ok := cvss["baseScore"].(float64); ok {
				info.Score = score
			}
			if severity, ok := cvss["baseSeverity"].(string); ok {
				info.Severity = severity
			}
			if info.Score > 0 {
				return info
			}
		}
	}
	return nil
}
