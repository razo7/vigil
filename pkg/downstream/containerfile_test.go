package downstream

import (
	"testing"
)

func TestExtractGoVersion(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			"standard FROM with golang",
			"FROM registry.access.redhat.com/ubi9/go-toolset:golang-1.25.3 AS builder\nRUN go build",
			"1.25.3",
		},
		{
			"golang with colon",
			"FROM golang:1.25.8-bookworm\nCOPY . .",
			"1.25.8",
		},
		{
			"golang with dash",
			"FROM registry.redhat.io/rhel9/go-toolset:golang-1.24.11\nRUN make",
			"1.24.11",
		},
		{
			"no golang in FROM",
			"FROM registry.access.redhat.com/ubi9/ubi-minimal:latest\nCOPY bin/manager /manager",
			"",
		},
		{
			"multi-stage build",
			"FROM golang:1.25.3 AS builder\nRUN go build\nFROM registry.access.redhat.com/ubi9/ubi-minimal:latest\nCOPY --from=builder /app /app",
			"1.25.3",
		},
		{
			"golang mentioned in ENV not FROM",
			"FROM ubi-minimal:latest\nENV GOLANG_VERSION=golang-1.25.9\nRUN dnf install",
			"1.25.9",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := extractGoVersion(tc.content)
			if got != tc.expected {
				t.Errorf("extractGoVersion() = %q, want %q", got, tc.expected)
			}
		})
	}
}
