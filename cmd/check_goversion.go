package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/razo7/vigil/pkg/goversion"
	"github.com/spf13/cobra"
)

var (
	checkDesired   string
	checkOperator  string
	checkBaseImage string
	checkVersion   string
)

var checkGoVersionCmd = &cobra.Command{
	Use:   "check-goversion",
	Short: "Check if a desired Go version is available in the downstream base image",
	Example: `  # Check if FAR downstream has Go 1.25.9
  vigil check-goversion --operator FAR --want 1.25.9

  # Check a specific operator version
  vigil check-goversion --operator FAR --want 1.25.9 --version 0.4

  # Check all operators
  vigil check-goversion --want 1.25.9`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if checkDesired == "" {
			return fmt.Errorf("--want is required")
		}

		operators := resolveOperators(checkOperator)

		for _, op := range operators {
			result, err := goversion.CheckGoVersion(op, checkDesired, checkBaseImage, checkVersion)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: %s: %v\n", op, err)
				continue
			}

			out, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(out))
		}
		return nil
	},
}

var operatorNames = map[string]string{
	"FAR":         "fence-agents-remediation",
	"SNR":         "self-node-remediation",
	"NHC":         "node-healthcheck-operator",
	"NMO":         "node-maintenance-operator",
	"MDR":         "machine-deletion-remediation",
	"SBR":         "storage-based-remediation",
	"NHC-CONSOLE": "node-remediation-console",
}

func resolveOperators(shortName string) []string {
	if shortName == "" {
		all := make([]string, 0, len(operatorNames))
		for _, v := range operatorNames {
			all = append(all, v)
		}
		return all
	}
	if full, ok := operatorNames[shortName]; ok {
		return []string{full}
	}
	return []string{shortName}
}

func init() {
	checkGoVersionCmd.Flags().StringVar(&checkDesired, "want", "", "Desired Go version (e.g., 1.25.9)")
	checkGoVersionCmd.Flags().StringVar(&checkDesired, "desired", "", "Desired Go version (deprecated, use --want)")
	checkGoVersionCmd.Flags().StringVar(&checkOperator, "operator", "", "Operator short name: FAR, SNR, NHC, NMO, MDR (default: all)")
	checkGoVersionCmd.Flags().StringVar(&checkBaseImage, "base-image", "", "Downstream base image name (auto-detected if omitted)")
	checkGoVersionCmd.Flags().StringVar(&checkVersion, "version", "", "Operator version to check (e.g., 0.4)")
	_ = checkGoVersionCmd.Flags().MarkDeprecated("desired", "use --want instead")
	rootCmd.AddCommand(checkGoVersionCmd)
}
