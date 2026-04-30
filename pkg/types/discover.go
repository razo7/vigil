package types

import "time"

type DiscoveredVuln struct {
	VulnID         string         `json:"vuln_id"`
	Description    string         `json:"description,omitempty"`
	CVEIDs         []string       `json:"cve_ids"`
	Package        string         `json:"package"`
	PackageSource  string         `json:"package_source"`
	Language       string         `json:"language"`
	LanguageSource string         `json:"language_source"`
	Reachability   string         `json:"reachability"`
	FixVersion     string         `json:"fix_version,omitempty"`
	CallPaths      []string       `json:"call_paths,omitempty"`
	ImportChain    string         `json:"import_chain,omitempty"`
	Severity       float64        `json:"severity"`
	SeverityLabel  string         `json:"severity_label"`
	Classification Classification `json:"classification"`
	Priority       Priority       `json:"priority"`
	HasTicket      bool           `json:"has_ticket"`
	TicketID       string         `json:"ticket_id,omitempty"`
	TicketStatus   string         `json:"ticket_status,omitempty"`
	Source         string         `json:"source"`
	CVEPublished   string         `json:"cve_published,omitempty"`
}

type DiscoverResult struct {
	Component  string           `json:"component"`
	RepoPath   string           `json:"repo_path"`
	GoVersion  string           `json:"go_version"`
	TotalVulns int              `json:"total_vulns"`
	WithTicket int              `json:"with_ticket"`
	NoTicket   int              `json:"no_ticket"`
	Vulns      []DiscoveredVuln `json:"vulns"`
	AssessedAt time.Time        `json:"assessed_at"`
}
