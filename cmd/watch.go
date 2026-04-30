package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/razo7/vigil/pkg/watch"
	"github.com/spf13/cobra"
)

var (
	watchComponent   string
	watchInterval    time.Duration
	watchOnce        bool
	watchRegistryDir string
	watchVersion     string
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Monitor blocked CVEs and re-check when downstream Go updates",
	Long: `Watch monitors CVEs classified as "Blocked by Go" and periodically
re-checks whether the required Go version is now available in the
downstream base image. When a CVE becomes fixable, it is promoted
and removed from the blocked registry.

The blocked registry is stored at <registry-dir>/blocked.json.
Use 'vigil scan' or 'vigil assess' to populate it automatically.`,
	Example: `  # One-time check for FAR blocked CVEs
  vigil watch --component FAR --once

  # Poll every 24 hours
  vigil watch --component FAR --interval 24h

  # Check all components once
  vigil watch --once`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if watchComponent == "" {
			return runWatchAll()
		}
		return runWatch(cmd.Context())
	},
}

func runWatch(ctx context.Context) error {
	operatorName := ""
	if full, ok := operatorNames[strings.ToUpper(watchComponent)]; ok {
		operatorName = full
	} else {
		operatorName = strings.ToLower(watchComponent)
	}

	opts := watch.Options{
		Component:    strings.ToUpper(watchComponent),
		RegistryDir:  watchRegistryDir,
		OperatorName: operatorName,
		Version:      watchVersion,
	}

	if watchOnce {
		promoted, err := watch.Run(ctx, opts)
		if err != nil {
			return err
		}
		return printWatchResult(promoted)
	}

	ticker := time.NewTicker(watchInterval)
	defer ticker.Stop()

	promoted, err := watch.Run(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Watch error: %v\n", err)
	} else {
		printWatchResult(promoted)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			fmt.Fprintf(os.Stderr, "\n--- Watch check at %s ---\n", time.Now().UTC().Format(time.RFC3339))
			promoted, err := watch.Run(ctx, opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Watch error: %v\n", err)
			} else {
				printWatchResult(promoted)
			}
		}
	}
}

func runWatchAll() error {
	ctx := context.Background()
	var allPromoted []watch.PromotedCVE

	for short, full := range operatorNames {
		opts := watch.Options{
			Component:    short,
			RegistryDir:  watchRegistryDir,
			Once:         true,
			OperatorName: full,
			Version:      watchVersion,
		}
		promoted, err := watch.Run(ctx, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s: %v\n", short, err)
			continue
		}
		allPromoted = append(allPromoted, promoted...)
	}

	return printWatchResult(allPromoted)
}

func printWatchResult(promoted []watch.PromotedCVE) error {
	if len(promoted) == 0 {
		return nil
	}

	type promotedOutput struct {
		TicketID          string `json:"ticket_id"`
		CVEID             string `json:"cve_id"`
		RequiredGo        string `json:"required_go"`
		DownstreamVersion string `json:"downstream_version"`
		Component         string `json:"component"`
	}

	var out []promotedOutput
	for _, p := range promoted {
		out = append(out, promotedOutput{
			TicketID:          p.Entry.TicketID,
			CVEID:             p.Entry.CVEID,
			RequiredGo:        p.Entry.RequiredGo,
			DownstreamVersion: p.DownstreamVersion,
			Component:         p.Entry.Component,
		})
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling promoted CVEs: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func init() {
	watchCmd.Flags().StringVar(&watchComponent, "component", "", "Component to watch (e.g., FAR, SNR, NHC)")
	watchCmd.Flags().DurationVar(&watchInterval, "interval", 168*time.Hour, "Check interval (default: 1 week)")
	watchCmd.Flags().BoolVar(&watchOnce, "once", false, "Run a single check and exit")
	watchCmd.Flags().StringVar(&watchRegistryDir, "registry-dir", ".vigil", "Directory for blocked CVE registry")
	watchCmd.Flags().StringVar(&watchVersion, "version", "", "Operator version to check (e.g., 0.4)")
	rootCmd.AddCommand(watchCmd)
}
