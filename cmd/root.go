package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "0.1.0"
)

var rootCmd = &cobra.Command{
	Use:   "claudeguard [path]",
	Short: "Universal dependency security scanner",
	Long: `claudeguard — Universal dependency security scanner

Automatically detects and scans dependencies across all major ecosystems:
npm, composer, pip, go, cargo, gem, maven, nuget, swift, and more.

Checks for:
  - Known vulnerabilities (via OSV.dev)
  - Supply chain integrity issues (typosquatting, repo injection)
  - License compliance risks (copyleft, unknown licenses)
  - Outdated dependencies`,
	Version:           version,
	Args:              cobra.MaximumNArgs(1),
	TraverseChildren:  true,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Add global flags
	rootCmd.PersistentFlags().StringP("format", "f", "table", "Output format: table, json")
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Only output errors and warnings")

	// Default action is scan
	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runScan(cmd, args)
	}
}

func getProjectPath(args []string) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}

	path, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("could not determine working directory: %w", err)
	}
	return path, nil
}
