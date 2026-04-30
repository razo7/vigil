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
