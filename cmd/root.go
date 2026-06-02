package cmd

import (
	"fmt"
	"os"

	"github.com/razo7/vigil/pkg/config"
	"github.com/razo7/vigil/pkg/lifecycle"
	"github.com/spf13/cobra"
)

var (
	forceColor bool
	configPath string
	appConfig  *config.Config
)

var rootCmd = &cobra.Command{
	Use:   "vigil",
	Short: "Deterministic CVE assessment tool for medik8s operators",
	Long: `Vigil assesses CVE tickets for medik8s operators by running govulncheck,
checking downstream base image compatibility, and classifying each CVE into
actionable categories: fixable-now, blocked-by-go, not-reachable, not-go,
or misassigned.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if configPath != "" {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			appConfig = cfg
		} else {
			appConfig = config.Default()
		}
		if eolThreshold != "" {
			appConfig.EOLThreshold = eolThreshold
		}
		return applyLifecycleConfig(appConfig)
	},
}

var eolThreshold string

func init() {
	rootCmd.PersistentFlags().BoolVar(&forceColor, "color", false, "Force colored output (useful in containers)")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to vigil.yaml config file (default: built-in component map)")
	rootCmd.PersistentFlags().StringVar(&eolThreshold, "eol-threshold", "", "Skip versions with less remaining support (e.g., 30d, 90d, 6m, 1y)")
}

func Execute() error {
	return rootCmd.Execute()
}

func getConfig() *config.Config {
	if appConfig != nil {
		return appConfig
	}
	if configPath != "" {
		cfg, err := config.Load(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: failed to load config %s: %v, using defaults\n", configPath, err)
			appConfig = config.Default()
			return appConfig
		}
		appConfig = cfg
		return appConfig
	}
	appConfig = config.Default()
	return appConfig
}

func applyLifecycleConfig(cfg *config.Config) error {
	if len(cfg.Lifecycle.OCPReleases) == 0 && len(cfg.Lifecycle.OperatorMappings) == 0 && len(cfg.Lifecycle.RHWAToOCP) == 0 {
		return nil
	}

	releases, mappings, rhwa, err := lifecycle.ConfigFromYAML(cfg.Lifecycle)
	if err != nil {
		return fmt.Errorf("parsing lifecycle config: %w", err)
	}
	lifecycle.SetConfig(releases, mappings, rhwa)
	return nil
}
