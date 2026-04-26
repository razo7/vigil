package assess

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/razo7/vigil/pkg/goversion"
)

type vulnDBResult struct {
	Ranges     []goversion.AffectedRange
	FixVersion string
	References []string
}

func fetchFromVulnDB(vulnID string) *vulnDBResult {
	url := fmt.Sprintf("https://api.osv.dev/v1/vulns/%s", vulnID)

	resp, err := http.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var entry osvEntry
	if err := json.Unmarshal(body, &entry); err != nil {
		return nil
	}

	result := &vulnDBResult{}

	for _, affected := range entry.Affected {
		for _, r := range affected.Ranges {
			parsed := parseOSVRangeEvents(r.Events)
			result.Ranges = append(result.Ranges, parsed...)
		}
	}
	for _, ar := range result.Ranges {
		if ar.Fixed != "" {
			result.FixVersion = ar.Fixed
			break
		}
	}

	for _, ref := range entry.References {
		if ref.URL != "" {
			result.References = append(result.References, ref.URL)
		}
	}

	return result
}

type osvEntry struct {
	ID         string         `json:"id"`
	Affected   []osvAffected  `json:"affected"`
	References []osvReference `json:"references"`
}

type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func parseOSVRangeEvents(events []osvEvent) []goversion.AffectedRange {
	var ranges []goversion.AffectedRange
	var current goversion.AffectedRange
	for _, ev := range events {
		if ev.Introduced != "" {
			current.Introduced = strings.TrimPrefix(ev.Introduced, "v")
		}
		if ev.Fixed != "" {
			current.Fixed = strings.TrimPrefix(ev.Fixed, "v")
			ranges = append(ranges, current)
			current = goversion.AffectedRange{}
		}
	}
	if current.Introduced != "" {
		ranges = append(ranges, current)
	}
	return ranges
}
