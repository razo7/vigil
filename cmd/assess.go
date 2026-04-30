package cmd

import (
	"fmt"
	"os"

	"github.com/razo7/vigil/pkg/assess"
	"github.com/razo7/vigil/pkg/fix"
	"github.com/razo7/vigil/pkg/report"
	"github.com/razo7/vigil/pkg/types"
	"github.com/spf13/cobra"
)

var (
	assessJira        bool
	assessSummaryFile string
	assessRepoPath    string
	assessFix         bool
)

var assessCmd = &cobra.Command{
	Use:   "assess <TICKET-ID>",
	Short: "Assess a single CVE ticket",
	Long: `Fetch a Jira CVE ticket, extract the CVE ID, run govulncheck for reachability
analysis, check downstream base image compatibility, and classify the CVE.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ticketID := args[0]

		result, err := assess.Run(cmd.Context(), assess.Options{
			TicketID: ticketID,
			RepoPath: assessRepoPath,
		})
		if err != nil {
			return fmt.Errorf("assessment failed: %w", err)
		}

		if err := printJSON(result); err != nil {
			return fmt.Errorf("marshaling result: %w", err)
		}

		if assessSummaryFile != "" {
			if err := report.WriteSanitizedSummary(assessSummaryFile, result); err != nil {
				return fmt.Errorf("writing summary: %w", err)
			}
		}

		if assessJira {
			if err := report.PostToJira(result); err != nil {
				return fmt.Errorf("posting to jira: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Posted assessment to %s\n", ticketID)
		}

		if result.Recommendation.Classification == types.BlockedByGo {
			recordBlockedCVE(result)
		}

		if assessFix && result.Recommendation.Classification == types.FixableNow {
			fmt.Fprintf(os.Stderr, "Classification is Fixable Now — running fix pipeline...\n")
			fixResult, fixErr := fix.Run(cmd.Context(), fix.Options{
				TicketID: ticketID,
				RepoPath: assessRepoPath,
				Strategy: fix.StrategyAuto,
				CreatePR: true,
				Jira:     assessJira,
			})
			if fixResult != nil {
				if jsonErr := printJSON(fixResult); jsonErr != nil {
					fmt.Fprintf(os.Stderr, "WARNING: marshaling fix result: %v\n", jsonErr)
				}
			}
			if fixErr != nil {
				fmt.Fprintf(os.Stderr, "WARNING: fix pipeline: %v\n", fixErr)
			}
		}

		return nil
	},
}

func init() {
	assessCmd.Flags().BoolVar(&assessJira, "jira", false, "Post assessment as Jira comment")
	assessCmd.Flags().StringVar(&assessSummaryFile, "summary-file", "", "Write sanitized summary to file")
	assessCmd.Flags().StringVar(&assessRepoPath, "repo-path", "", "Path to operator repo (auto-detected from Jira component if omitted)")
	assessCmd.Flags().BoolVar(&assessFix, "fix", false, "Auto-fix if classified as Fixable Now")
	rootCmd.AddCommand(assessCmd)
}
