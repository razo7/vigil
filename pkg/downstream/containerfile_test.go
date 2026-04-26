package downstream

import (
	"testing"
)

func TestDownstreamBranch(t *testing.T) {
	tests := []struct {
		operator string
		version  string
		expected string
	}{
		{"fence-agents-remediation", "0.8", "far-0-8"},
		{"fence-agents-remediation", "0.4", "far-0-4"},
		{"self-node-remediation", "0.10", "snr-0-10"},
		{"node-healthcheck-controller", "0.9", "nhc-0-9"},
		{"node-maintenance-operator", "5.4", "nmo-5-4"},
		{"machine-deletion-remediation", "0.4", "mdr-0-4"},
		{"fence-agents-remediation", "", "main"},
		{"unknown-operator", "1.0", "main"},
	}

	for _, tc := range tests {
		t.Run(tc.operator+"/"+tc.version, func(t *testing.T) {
			got := downstreamBranch(tc.operator, tc.version)
			if got != tc.expected {
				t.Errorf("downstreamBranch(%q, %q) = %q, want %q", tc.operator, tc.version, got, tc.expected)
			}
		})
	}
}

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
