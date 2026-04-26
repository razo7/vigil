package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	scanComponent   string
	scanJQL         string
	scanJira        bool
	scanSummaryFile string
	scanRepoPath    string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Batch assess all CVE tickets for a component",
	Long: `Find all open CVE tickets for the specified component via JQL query,
then assess each one.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if scanComponent == "" && scanJQL == "" {
			return fmt.Errorf("either --component or --jql is required")
		}
		// TODO: implement batch scanning in Phase 2
		return fmt.Errorf("scan command not yet implemented")
	},
}

func init() {
	scanCmd.Flags().StringVar(&scanComponent, "component", "", "Component name (e.g., FAR)")
	scanCmd.Flags().StringVar(&scanJQL, "jql", "", "Custom JQL query")
	scanCmd.Flags().BoolVar(&scanJira, "jira", false, "Post assessments as Jira comments")
	scanCmd.Flags().StringVar(&scanSummaryFile, "summary-file", "", "Write aggregate summary to file")
	scanCmd.Flags().StringVar(&scanRepoPath, "repo-path", ".", "Path to operator repo")
	rootCmd.AddCommand(scanCmd)
}
