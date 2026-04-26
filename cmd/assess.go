package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/razo7/vigil/pkg/assess"
	"github.com/razo7/vigil/pkg/report"
	"github.com/spf13/cobra"
)

var (
	assessJira        bool
	assessSummaryFile string
	assessRepoPath    string
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

		out, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling result: %w", err)
		}
		fmt.Println(string(out))

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

		return nil
	},
}

func init() {
	assessCmd.Flags().BoolVar(&assessJira, "jira", false, "Post assessment as Jira comment")
	assessCmd.Flags().StringVar(&assessSummaryFile, "summary-file", "", "Write sanitized summary to file")
	assessCmd.Flags().StringVar(&assessRepoPath, "repo-path", ".", "Path to operator repo")
	rootCmd.AddCommand(assessCmd)
}
