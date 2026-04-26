package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "vigil",
	Short: "Deterministic CVE assessment tool for medik8s operators",
	Long: `Vigil assesses CVE tickets for medik8s operators by running govulncheck,
checking downstream base image compatibility, and classifying each CVE into
actionable categories: fixable-now, blocked-by-go, not-reachable, not-go,
or misassigned.`,
}

func Execute() error {
	return rootCmd.Execute()
}
