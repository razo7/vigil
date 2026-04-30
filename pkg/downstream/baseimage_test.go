package downstream

import (
	"testing"
)

func TestExtractBaseImage(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			"ubi9 go-toolset",
			"FROM registry.access.redhat.com/ubi9/go-toolset:golang-1.25.3 AS builder\nRUN go build",
			"registry.access.redhat.com/ubi9/go-toolset",
		},
		{
			"official golang",
			"FROM golang:1.25.8-bookworm\nCOPY . .",
			"golang",
		},
		{
			"rhel9 go-toolset",
			"FROM registry.redhat.io/rhel9/go-toolset:golang-1.24.11\nRUN make",
			"registry.redhat.io/rhel9/go-toolset",
		},
		{
			"no golang FROM",
			"FROM registry.access.redhat.com/ubi9/ubi-minimal:latest\nCOPY bin/manager /manager",
			"",
		},
		{
			"multi-stage picks golang stage",
			"FROM golang:1.25.3 AS builder\nRUN go build\nFROM ubi-minimal:latest\nCOPY --from=builder /app /app",
			"golang",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractBaseImage(tc.content)
			if got != tc.expected {
				t.Errorf("ExtractBaseImage() = %q, want %q", got, tc.expected)
			}
		})
	}
}
