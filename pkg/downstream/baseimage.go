package downstream

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/razo7/vigil/pkg/classify"
)

var baseImageRe = regexp.MustCompile(`^FROM\s+(\S+?)(?::|\s)`)
var goTagRe = regexp.MustCompile(`^golang-v?(\d+\.\d+(?:\.\d+)?)`)

func ExtractBaseImage(containerfileContent string) string {
	for _, line := range strings.Split(containerfileContent, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(trimmed), "FROM") {
			continue
		}
		if !goVersionRe.MatchString(trimmed) {
			continue
		}
		if m := baseImageRe.FindStringSubmatch(trimmed); len(m) == 2 {
			parts := strings.SplitN(m[1], ":", 2)
			return parts[0]
		}
	}
	return ""
}

func LatestGoVersion(baseImage string) (string, error) {
	if baseImage == "" {
		return "", fmt.Errorf("empty base image")
	}

	tags, err := skopeoListTags(baseImage)
	if err != nil {
		return "", fmt.Errorf("listing tags for %s: %w", baseImage, err)
	}

	var best string
	for _, tag := range tags {
		m := goTagRe.FindStringSubmatch(tag)
		if m == nil {
			continue
		}
		ver := m[1]
		if best == "" || classify.CompareVersions(ver, best) > 0 {
			best = ver
		}
	}

	if best == "" {
		return "", fmt.Errorf("no golang tags found for %s", baseImage)
	}
	return best, nil
}
