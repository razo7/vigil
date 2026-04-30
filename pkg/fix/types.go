package fix

import (
	"github.com/razo7/vigil/pkg/types"
)

type StrategyName string

const (
	StrategyGoMinor    StrategyName = "gominor"
	StrategyDirect     StrategyName = "direct"
	StrategyTransitive StrategyName = "transitive"
	StrategyReplace    StrategyName = "replace"
	StrategyMajor      StrategyName = "major"
	StrategyAuto       StrategyName = "auto"
)

type Strategy interface {
	Name() StrategyName
	Risk() int
	Apply(opts StrategyOptions) (*StrategyResult, error)
}

type StrategyOptions struct {
	RepoPath   string
	Package    string
	Module     string
	FixVersion string
	CVEID      string
	DryRun     bool

	// GoMinor-specific
	OperatorName    string
	ImageName       string
	OperatorVersion string
}

type StrategyResult struct {
	Strategy StrategyName `json:"strategy"`
	Risk     int          `json:"risk"`
	Command  string       `json:"command"`
	Changes  []string     `json:"changes,omitempty"`
	Message  string       `json:"message,omitempty"`
}

type Options struct {
	TicketID     string
	RepoPath     string
	Strategy     StrategyName
	DryRun       bool
	ApproveMajor bool
	CreatePR     bool
	Jira         bool
	RunTests     bool
}

type Result struct {
	TicketID   string            `json:"ticket_id"`
	CVEID      string            `json:"cve_id"`
	Strategy   StrategyName      `json:"strategy"`
	Risk       int               `json:"risk"`
	Validation *ValidationResult `json:"validation,omitempty"`
	PRURL      string            `json:"pr_url,omitempty"`
	Assessment *types.Result     `json:"assessment,omitempty"`
	DryRun     bool              `json:"dry_run"`
}

type StepResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Output string `json:"output,omitempty"`
}

type ValidationResult struct {
	Steps      []StepResult `json:"steps"`
	CVERemoved bool         `json:"cve_removed"`
	Passed     bool         `json:"passed"`
}
