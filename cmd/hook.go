package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/ClauGuard/clauguard/internal/advisory"
	"github.com/ClauGuard/clauguard/internal/detector"
	"github.com/ClauGuard/clauguard/internal/integrity"
	"github.com/ClauGuard/clauguard/internal/scanner"
	"github.com/ClauGuard/clauguard/pkg/models"
)

// hookContext is the JSON payload Claude Code sends via stdin.
type hookContext struct {
	Session struct {
		WorkingDirectory string `json:"workingDirectory"`
	} `json:"session"`
	ToolInput json.RawMessage `json:"tool_input"`
	Input     json.RawMessage `json:"input"`
}

type toolInputFile struct {
	FilePath string `json:"file_path"`
}

var manifestPattern = regexp.MustCompile(
	`(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|` +
		`composer\.json|composer\.lock|` +
		`requirements\.txt|Pipfile|pyproject\.toml|poetry\.lock|` +
		`go\.mod|go\.sum|` +
		`Cargo\.toml|Cargo\.lock|` +
		`Gemfile|Gemfile\.lock|` +
		`pom\.xml|build\.gradle|build\.gradle\.kts|` +
		`\.csproj|packages\.config|` +
		`Package\.swift|` +
		`Podfile|Podfile\.lock|` +
		`pubspec\.yaml|pubspec\.lock)$`,
)

var hookCmd = &cobra.Command{
	Use:    "hook",
	Short:  "Claude Code hook handlers",
	Hidden: true,
}

var hookPostEditCmd = &cobra.Command{
	Use:   "post-edit",
	Short: "PostToolUse hook — scan after dependency manifest edits",
	RunE:  runHookPostEdit,
}

var hookPreCommitCmd = &cobra.Command{
	Use:   "pre-commit",
	Short: "PreToolUse hook — block commits with critical issues",
	RunE:  runHookPreCommit,
}

func init() {
	rootCmd.AddCommand(hookCmd)
	hookCmd.AddCommand(hookPostEditCmd)
	hookCmd.AddCommand(hookPreCommitCmd)
}

func readHookContext() (*hookContext, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("failed to read stdin: %w", err)
	}
	var ctx hookContext
	if err := json.Unmarshal(data, &ctx); err != nil {
		return nil, fmt.Errorf("failed to parse hook context: %w", err)
	}
	return &ctx, nil
}

func (ctx *hookContext) filePath() string {
	var f toolInputFile
	if len(ctx.ToolInput) > 0 {
		if json.Unmarshal(ctx.ToolInput, &f) == nil && f.FilePath != "" {
			return f.FilePath
		}
	}
	if len(ctx.Input) > 0 {
		if json.Unmarshal(ctx.Input, &f) == nil && f.FilePath != "" {
			return f.FilePath
		}
	}
	return ""
}

func runHookPostEdit(cmd *cobra.Command, args []string) error {
	ctx, err := readHookContext()
	if err != nil {
		return nil // silently pass on parse errors — don't block the user
	}

	filePath := ctx.filePath()
	if filePath == "" || !manifestPattern.MatchString(filePath) {
		return nil // not a manifest edit, nothing to do
	}

	dir := ctx.Session.WorkingDirectory
	if dir == "" {
		return nil
	}

	criticalVulns, integrityIssues := scanForCritical(dir)
	total := criticalVulns + integrityIssues

	if total > 0 {
		fmt.Fprintf(os.Stderr, "ClauGuard found %d critical/high severity issue(s) after editing %s:\n", total, filePath)
		if criticalVulns > 0 {
			fmt.Fprintf(os.Stderr, "  - %d critical/high vulnerability(ies)\n", criticalVulns)
		}
		if integrityIssues > 0 {
			fmt.Fprintf(os.Stderr, "  - %d supply chain integrity issue(s)\n", integrityIssues)
		}
		fmt.Fprintf(os.Stderr, "\nReview these findings before proceeding.\n")
		os.Exit(2)
	}

	return nil
}

func runHookPreCommit(cmd *cobra.Command, args []string) error {
	ctx, err := readHookContext()
	if err != nil {
		return nil
	}

	dir := ctx.Session.WorkingDirectory
	if dir == "" {
		return nil
	}

	criticalVulns, integrityIssues := scanForCritical(dir)
	total := criticalVulns + integrityIssues

	if total > 0 {
		fmt.Fprintf(os.Stderr, "ClauGuard blocked this commit — %d critical issue(s) found:\n", total)
		if criticalVulns > 0 {
			fmt.Fprintf(os.Stderr, "  - %d critical vulnerability(ies)\n", criticalVulns)
		}
		if integrityIssues > 0 {
			fmt.Fprintf(os.Stderr, "  - %d supply chain integrity issue(s)\n", integrityIssues)
		}
		fmt.Fprintf(os.Stderr, "\nRun 'clauguard scan %s' for full report.\n", dir)
		os.Exit(2)
	}

	return nil
}

// scanForCritical runs vulnerability and integrity checks, returning counts of critical/high findings.
func scanForCritical(dir string) (criticalVulns int, integrityIssues int) {
	manifests, err := detector.Detect(dir)
	if err != nil {
		return 0, 0
	}

	deps, _, err := scanner.ParseAll(manifests)
	if err != nil {
		return 0, 0
	}

	// Filter to production deps only.
	var prod []models.Dependency
	for _, d := range deps {
		if !d.IsDev {
			prod = append(prod, d)
		}
	}

	if len(prod) == 0 {
		return 0, 0
	}

	// Vulnerability check.
	vulns, err := advisory.NewOSVClient().QueryBatch(prod)
	if err == nil {
		for _, v := range vulns {
			if v.Severity == models.SeverityCritical || v.Severity == models.SeverityHigh {
				criticalVulns++
			}
		}
	}

	// Integrity check.
	checker := integrity.NewChecker()
	issues := checker.Check(prod)
	for _, i := range issues {
		if i.Severity == models.SeverityCritical || i.Severity == models.SeverityHigh {
			integrityIssues++
		}
	}

	return criticalVulns, integrityIssues
}
