package types

import "time"

type Classification string

const (
	FixableNow   Classification = "Fixable Now"
	BlockedByGo  Classification = "Blocked by Go"
	NotReachable Classification = "Not Reachable"
	NotGo        Classification = "Not Go"
	Misassigned  Classification = "Misassigned"
)

type Priority string

const (
	PriorityCritical    Priority = "Critical"
	PriorityHigh        Priority = "High"
	PriorityMedium      Priority = "Medium"
	PriorityBlocked     Priority = "Blocked"
	PriorityLow         Priority = "Low"
	PriorityManual      Priority = "Needs manual review"
	PriorityMisassigned Priority = "Misassigned"
)

type SupportPhase string

const (
	PhaseGA          SupportPhase = "Full Support"
	PhaseEUS1        SupportPhase = "EUS1"
	PhaseMaintenance SupportPhase = "Maintenance"
	PhaseEUS2        SupportPhase = "EUS2"
	PhaseEUS3        SupportPhase = "EUS3"
	PhaseEOL         SupportPhase = "EOL"
	PhaseUnknown     SupportPhase = "Unknown"
)

type SourceInfo struct {
	TicketID                string   `json:"ticket_id"`
	AffectedOperatorVersion string   `json:"affected operator version"`
	Status                  string   `json:"status"`
	Resolution              string   `json:"resolution,omitempty"`
	Reporter                string   `json:"reporter,omitempty"`
	Assignee                string   `json:"assignee,omitempty"`
	DueDate                 string   `json:"due_date,omitempty"`
	JiraPriority            string   `json:"jira_priority,omitempty"`
	Labels                  string   `json:"labels,omitempty"`
	AffectsRHWAVersions     string   `json:"affects_rhwa_versions,omitempty"`
	TicketFixVersions       string   `json:"ticket_fix_versions,omitempty"`
	OCPSupport              []string `json:"rhwa-ocp_support"`
}

type VulnInfo struct {
	CVEID              string  `json:"cve_id"`
	Description        string  `json:"description,omitempty"`
	Severity           float64 `json:"severity"`
	SeverityLabel      string  `json:"severity_label"`
	Language           string  `json:"language,omitempty"`
	VulnID             string  `json:"vuln_id,omitempty"`
	Package            string  `json:"package,omitempty"`
	FixVersion         string  `json:"fix_version,omitempty"`
	FixFunctions       string  `json:"fix_functions,omitempty"`
	AffectedGoVersions string  `json:"affected_go_versions,omitempty"`
	CWE                string  `json:"cwe,omitempty"`
	CWEDescription     string  `json:"cwe_description,omitempty"`
	References         string  `json:"references,omitempty"`
}

type UpstreamInfo struct {
	Branch    string `json:"branch"`
	GoVersion string `json:"go_version"`
}

type DownstreamInfo struct {
	Branch    string `json:"branch,omitempty"`
	GoVersion string `json:"go_version,omitempty"`
}

type BranchAnalysis struct {
	Reachability     string          `json:"reachability"`
	CatalogComponent string          `json:"catalog_component,omitempty"`
	Upstream         UpstreamInfo    `json:"upstream"`
	Downstream       *DownstreamInfo `json:"downstream,omitempty"`
	CallPaths        []string        `json:"call_paths,omitempty"`
}

type FixUpstreamInfo struct {
	Reachability string   `json:"reachability"`
	GoVersion    string   `json:"go_version"`
	CallPaths    []string `json:"call_paths,omitempty"`
}

type AnalysisInfo struct {
	ReleaseBranch *BranchAnalysis  `json:"release_branch,omitempty"`
	FixUpstream   *FixUpstreamInfo `json:"fix_upstream?,omitempty"`
}

type RecommendationInfo struct {
	Classification  Classification `json:"classification"`
	Priority        Priority       `json:"priority"`
	Action          string         `json:"action"`
	MisassignReason string         `json:"misassign_reason,omitempty"`
}

type Result struct {
	Source         SourceInfo         `json:"source"`
	Vulnerability  VulnInfo           `json:"vulnerability"`
	Analysis       AnalysisInfo       `json:"analysis"`
	Recommendation RecommendationInfo `json:"recommendation"`
	AssessedAt     time.Time          `json:"assessed_at"`
	Version        string             `json:"vigil_version"`
}
