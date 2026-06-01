package types

import "time"

type DetectionOutput struct {
	Findings   []*Result         `json:"findings"`
	Discovered []DiscoveredVuln  `json:"discovered"`
	Metadata   DetectionMetadata `json:"metadata"`
}

type DetectionMetadata struct {
	Component string    `json:"component"`
	RepoPath  string    `json:"repo_path"`
	ScannedAt time.Time `json:"scanned_at"`
	GoVersion string    `json:"go_version"`
}

type BatchFixOutput struct {
	Fixes []BatchFixResult `json:"fixes"`
}

type BatchFixResult struct {
	TicketID string `json:"ticket"`
	CVEID    string `json:"cve"`
	Strategy string `json:"strategy"`
	PRURL    string `json:"pr_url,omitempty"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
}
