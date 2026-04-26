package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	checkDesired   string
	checkBaseImage string
)

var checkGoVersionCmd = &cobra.Command{
	Use:   "check-goversion",
	Short: "Check if a desired Go version is available in the downstream base image",
	RunE: func(cmd *cobra.Command, args []string) error {
		if checkDesired == "" {
			return fmt.Errorf("--desired is required")
		}
		// TODO: implement base image version checking
		return fmt.Errorf("check-goversion command not yet implemented")
	},
}

func init() {
	checkGoVersionCmd.Flags().StringVar(&checkDesired, "desired", "", "Desired Go version (e.g., 1.25.9)")
	checkGoVersionCmd.Flags().StringVar(&checkBaseImage, "base-image", "", "Downstream base image to check")
	rootCmd.AddCommand(checkGoVersionCmd)
}
