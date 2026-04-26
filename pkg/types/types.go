package types

import "time"

type Classification string

const (
	FixableNow   Classification = "fixable-now"
	BlockedByGo  Classification = "blocked-by-go"
	NotReachable Classification = "not-reachable"
	NotGo        Classification = "not-go"
	Misassigned  Classification = "misassigned"
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
	PhaseGA          SupportPhase = "GA"
	PhaseEUS1        SupportPhase = "EUS1"
	PhaseMaintenance SupportPhase = "Maintenance"
	PhaseEUS2        SupportPhase = "EUS2"
	PhaseEUS3        SupportPhase = "EUS3"
	PhaseEOL         SupportPhase = "EOL"
	PhaseUnknown     SupportPhase = "Unknown"
)

type Result struct {
	TicketID       string         `json:"ticket_id"`
	CVEID          string         `json:"cve_id"`
	CVESource      string         `json:"cve_source"`
	Severity       float64        `json:"severity"`
	SeverityLabel  string         `json:"severity_label"`
	Package        string         `json:"package"`
	Classification Classification `json:"classification"`
	Priority       Priority       `json:"priority"`

	OperatorVersion string       `json:"operator_version"`
	OCPVersion      string       `json:"ocp_version"`
	SupportPhase    SupportPhase `json:"support_phase"`

	Reachability    string `json:"reachability"`
	VulnID          string `json:"vuln_id"`
	FixVersion      string `json:"fix_version"`
	CurrentGo       string `json:"current_go"`
	DownstreamGo    string `json:"downstream_go"`
	CallPath        string `json:"call_path,omitempty"`
	Recommendation  string `json:"recommendation"`
	MisassignReason string `json:"misassign_reason,omitempty"`

	MainBranch *MainBranchResult `json:"main_branch,omitempty"`

	Operator   string    `json:"operator"`
	AssessedAt time.Time `json:"assessed_at"`
	Version    string    `json:"vigil_version"`
}

type MainBranchResult struct {
	Reachability string `json:"reachability"`
	VulnID       string `json:"vuln_id,omitempty"`
	FixVersion   string `json:"fix_version,omitempty"`
	CurrentGo    string `json:"current_go"`
	CallPath     string `json:"call_path,omitempty"`
	Package      string `json:"package,omitempty"`
}
