package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kemaldelalic/claudeguard/internal/advisory"
	"github.com/kemaldelalic/claudeguard/internal/detector"
	"github.com/kemaldelalic/claudeguard/internal/reporter"
	"github.com/kemaldelalic/claudeguard/internal/scanner"
	"github.com/kemaldelalic/claudeguard/pkg/models"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a project for dependency vulnerabilities",
	Long:  `Scan detects all dependency files in a project and checks them against known vulnerability databases.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().Bool("skip-vuln", false, "Skip vulnerability checks")
	scanCmd.Flags().Bool("skip-license", false, "Skip license checks")
	scanCmd.Flags().Bool("skip-outdated", false, "Skip outdated dependency checks")
	scanCmd.Flags().Bool("dev", false, "Include dev dependencies in scan")
}

func runScan(cmd *cobra.Command, args []string) error {
	projectPath, err := getProjectPath(args)
	if err != nil {
		return err
	}

	format, _ := cmd.Flags().GetString("format")
	skipVuln, _ := cmd.Flags().GetBool("skip-vuln")
	includeDev, _ := cmd.Flags().GetBool("dev")

	// Step 1: Detect manifests
	fmt.Fprintf(os.Stderr, "Scanning %s...\n", projectPath)

	manifests, err := detector.Detect(projectPath)
	if err != nil {
		return fmt.Errorf("detection failed: %w", err)
	}

	if len(manifests) == 0 {
		fmt.Fprintf(os.Stderr, "No dependency files found in %s\n", projectPath)
		return nil
	}

	ecosystems := detector.DetectedEcosystems(manifests)
	fmt.Fprintf(os.Stderr, "Found %d manifest(s) across %d ecosystem(s)\n", len(manifests), len(ecosystems))

	// Step 2: Parse dependencies
	deps, err := scanner.ParseAll(manifests)
	if err != nil {
		return fmt.Errorf("parsing failed: %w", err)
	}

	// Filter dev deps unless --dev flag is set
	if !includeDev {
		deps = filterProdDeps(deps)
	}

	fmt.Fprintf(os.Stderr, "Parsed %d dependencies\n", len(deps))

	result := &models.ScanResult{
		ProjectPath:  projectPath,
		Dependencies: deps,
		Ecosystems:   ecosystems,
	}

	// Step 3: Check vulnerabilities
	if !skipVuln && len(deps) > 0 {
		fmt.Fprintf(os.Stderr, "Checking vulnerabilities via OSV.dev...\n")
		osvClient := advisory.NewOSVClient()
		vulns, err := osvClient.QueryBatch(deps)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: vulnerability check failed: %v\n", err)
		} else {
			result.Vulnerabilities = vulns
		}
	}

	// Step 4: Output results
	outputFormat := reporter.FormatTable
	if format == "json" {
		outputFormat = reporter.FormatJSON
	}

	if err := reporter.Report(os.Stdout, result, outputFormat); err != nil {
		return fmt.Errorf("report failed: %w", err)
	}

	// Exit with appropriate code
	exitCode := result.ExitCode()
	if exitCode != 0 {
		os.Exit(exitCode)
	}

	return nil
}

func filterProdDeps(deps []models.Dependency) []models.Dependency {
	var prod []models.Dependency
	for _, d := range deps {
		if !d.IsDev {
			prod = append(prod, d)
		}
	}
	return prod
}
