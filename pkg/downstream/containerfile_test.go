package downstream

import (
	"testing"
)

func TestDownstreamBranches(t *testing.T) {
	tests := []struct {
		operator string
		version  string
		expected []string
	}{
		{"fence-agents-remediation", "0.8", []string{"far-0-8", "rhwa-far-0.8-rhel-8", "rhwa-far-0.8-rhel-9"}},
		{"fence-agents-remediation", "0.4", []string{"far-0-4", "rhwa-far-0.4-rhel-8", "rhwa-far-0.4-rhel-9"}},
		{"self-node-remediation", "0.10", []string{"snr-0-10", "rhwa-snr-0.10-rhel-8", "rhwa-snr-0.10-rhel-9"}},
		{"fence-agents-remediation", "", []string{"main"}},
		{"unknown-operator", "1.0", []string{"main"}},
	}

	for _, tc := range tests {
		t.Run(tc.operator+"/"+tc.version, func(t *testing.T) {
			got := downstreamBranches(tc.operator, tc.version)
			if len(got) != len(tc.expected) {
				t.Fatalf("downstreamBranches(%q, %q) returned %d branches, want %d: %v", tc.operator, tc.version, len(got), len(tc.expected), got)
			}
			for i := range got {
				if got[i] != tc.expected[i] {
					t.Errorf("branch[%d] = %q, want %q", i, got[i], tc.expected[i])
				}
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
			"openshift golang builder with v prefix",
			"FROM registry-proxy.engineering.redhat.com/rh-osbs/openshift-golang-builder:v1.20.12-202504121010.g92d4921.el8 AS builder\nRUN go build",
			"1.20.12",
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
