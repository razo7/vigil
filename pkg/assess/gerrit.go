package assess

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var (
	clNumberRe    = regexp.MustCompile(`go-review\.googlesource\.com/c/go/\+/(\d+)`)
	diffFileRe    = regexp.MustCompile(`^diff --git a/(.+) b/`)
	hunkFuncRe    = regexp.MustCompile(`^@@[^@]+@@\s+func\s+(?:\([^)]+\)\s+)?(\w+)\s*[\(\[]`)
	changedFuncRe = regexp.MustCompile(`^[+-]\s*func\s+(?:\([^)]+\)\s+)?(\w+)\s*[\(\[]`)
)

func fetchFixFunctions(goReviewURL string) string {
	m := clNumberRe.FindStringSubmatch(goReviewURL)
	if m == nil {
		return ""
	}
	clNumber := m[1]

	patchURL := fmt.Sprintf("https://go-review.googlesource.com/changes/%s/revisions/current/patch", clNumber)
	resp, err := http.Get(patchURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return ""
	}

	return parseFixFunctions(string(decoded))
}

func parseFixFunctions(patch string) string {
	var currentFile string
	seen := make(map[string]bool)
	var results []string

	for _, line := range strings.Split(patch, "\n") {
		if m := diffFileRe.FindStringSubmatch(line); m != nil {
			currentFile = m[1]
			continue
		}

		if currentFile == "" {
			continue
		}
		if strings.HasSuffix(currentFile, "_test.go") || !strings.HasSuffix(currentFile, ".go") {
			continue
		}

		if m := hunkFuncRe.FindStringSubmatch(line); m != nil {
			key := currentFile + ":" + m[1]
			if !seen[key] {
				seen[key] = true
				results = append(results, key)
			}
		}

		if m := changedFuncRe.FindStringSubmatch(line); m != nil {
			key := currentFile + ":" + m[1]
			if !seen[key] {
				seen[key] = true
				results = append(results, key)
			}
		}
	}

	return strings.Join(results, ", ")
}
