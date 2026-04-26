package classify

import (
	"strconv"
	"strings"
)

// CompareVersions compares two version strings (e.g., "1.25.9" vs "1.25.3").
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
// Handles versions with or without "go" prefix (e.g., "go1.25.9").
func CompareVersions(a, b string) int {
	a = strings.TrimPrefix(a, "go")
	b = strings.TrimPrefix(b, "go")

	aParts := splitVersion(a)
	bParts := splitVersion(b)

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		var av, bv int
		if i < len(aParts) {
			av = aParts[i]
		}
		if i < len(bParts) {
			bv = bParts[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []int {
	parts := strings.Split(v, ".")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			continue
		}
		result = append(result, n)
	}
	return result
}
