package cmd

import (
	"fmt"
	"os"

	"github.com/razo7/vigil/pkg/fix"
	"github.com/razo7/vigil/pkg/jira"
	"github.com/spf13/cobra"
)

var (
	fixStrategy     string
	fixDryRun       bool
	fixJira         bool
	fixApproveMajor bool
	fixRepoPath     string
	fixCreatePR     bool
	fixRunTests     bool
)

var fixCmd = &cobra.Command{
	Use:   "fix <TICKET-ID>",
	Short: "Auto-fix a Fixable Now CVE",
	Long: `Assess the ticket, bump the vulnerable dependency using a risk-ascending
strategy cascade (gominor → direct → transitive → replace → major),
validate with govulncheck, and optionally create a draft PR and update Jira.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ticketID := args[0]

		result, err := fix.Run(cmd.Context(), fix.Options{
			TicketID:     ticketID,
			RepoPath:     fixRepoPath,
			Strategy:     fix.StrategyName(fixStrategy),
			DryRun:       fixDryRun,
			ApproveMajor: fixApproveMajor,
			CreatePR:     fixCreatePR,
			Jira:         fixJira,
			RunTests:     fixRunTests,
		})

		if result != nil {
			if jsonErr := printJSON(result); jsonErr != nil {
				fmt.Fprintf(os.Stderr, "WARNING: marshaling result: %v\n", jsonErr)
			}
		}

		if err != nil {
			return err
		}

		if fixJira && result != nil && result.PRURL != "" {
			if jiraErr := postFixToJira(ticketID, result); jiraErr != nil {
				fmt.Fprintf(os.Stderr, "WARNING: Jira update failed: %v\n", jiraErr)
			}
		}

		return nil
	},
}

func postFixToJira(ticketID string, result *fix.Result) error {
	client, err := jira.NewClient()
	if err != nil {
		return err
	}

	prTitle := fmt.Sprintf("Fix %s: bump dependency", result.CVEID)
	if err := client.LinkPR(ticketID, result.PRURL, prTitle); err != nil {
		return fmt.Errorf("linking PR: %w", err)
	}

	if err := client.AddLabel(ticketID, "vigil-fix"); err != nil {
		return fmt.Errorf("adding label: %w", err)
	}

	comment := fmt.Sprintf("vigil fix: %s resolved via %s strategy (risk %d)\nPR: %s",
		result.CVEID, result.Strategy, result.Risk, result.PRURL)
	if err := client.PostComment(ticketID, comment); err != nil {
		return fmt.Errorf("posting comment: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Linked PR and updated %s\n", ticketID)
	return nil
}

func init() {
	fixCmd.Flags().StringVar(&fixStrategy, "strategy", "auto", "Strategy: auto|gominor|direct|transitive|replace|major")
	fixCmd.Flags().BoolVar(&fixDryRun, "dry-run", false, "Show what would change without modifying")
	fixCmd.Flags().BoolVar(&fixJira, "jira", false, "Post status and link PR to Jira (private comment)")
	fixCmd.Flags().BoolVar(&fixApproveMajor, "approve-major", false, "Allow major version bumps (risk 4)")
	fixCmd.Flags().StringVar(&fixRepoPath, "repo-path", "", "Override repo path")
	fixCmd.Flags().BoolVar(&fixCreatePR, "pr", true, "Create draft PR")
	fixCmd.Flags().BoolVar(&fixRunTests, "test", false, "Run go test in validation")
	rootCmd.AddCommand(fixCmd)
}
