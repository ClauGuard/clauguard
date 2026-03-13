package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/ClauGuard/clauguard/internal/advisory"
	"github.com/ClauGuard/clauguard/internal/detector"
	"github.com/ClauGuard/clauguard/internal/integrity"
	"github.com/ClauGuard/clauguard/internal/scanner"
	"github.com/ClauGuard/clauguard/pkg/models"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run as an MCP server (for Claude Code integration)",
	Long:  `Starts ClauGuard as a Model Context Protocol server over stdio, exposing scan tools for use by Claude Code and other MCP clients.`,
	RunE:  runMCP,
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}

// Tool argument types — struct tags drive JSON Schema generation.

type scanArgs struct {
	Path          string `json:"path" jsonschema:"required,directory path to scan for dependencies"`
	SkipVuln      bool   `json:"skip_vuln,omitempty" jsonschema:"skip vulnerability checks"`
	SkipIntegrity bool   `json:"skip_integrity,omitempty" jsonschema:"skip supply chain integrity checks"`
	SkipLicense   bool   `json:"skip_license,omitempty" jsonschema:"skip license compliance checks"`
	IncludeDev    bool   `json:"include_dev,omitempty" jsonschema:"include dev dependencies in scan"`
}

type integrityArgs struct {
	Path       string `json:"path" jsonschema:"required,directory path to scan"`
	IncludeDev bool   `json:"include_dev,omitempty" jsonschema:"include dev dependencies"`
}

type vulnArgs struct {
	Path       string `json:"path" jsonschema:"required,directory path to scan"`
	IncludeDev bool   `json:"include_dev,omitempty" jsonschema:"include dev dependencies"`
}

type licenseArgs struct {
	Path       string `json:"path" jsonschema:"required,directory path to scan"`
	IncludeDev bool   `json:"include_dev,omitempty" jsonschema:"include dev dependencies"`
}

func runMCP(cmd *cobra.Command, args []string) error {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "clauguard",
		Version: version,
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan",
		Description: "Full dependency security scan — checks vulnerabilities (OSV.dev), supply chain integrity (typosquatting), and license compliance across all ecosystems (npm, pip, go, cargo, gem, composer, etc.)",
	}, handleScan)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "check_integrity",
		Description: "Check dependencies for supply chain integrity issues: typosquatting (Levenshtein, homoglyph, delimiter confusion, combosquatting) and known malicious packages",
	}, handleIntegrity)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "check_vulnerabilities",
		Description: "Check dependencies for known vulnerabilities via OSV.dev database",
	}, handleVuln)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "check_licenses",
		Description: "Check dependency licenses for compliance risks (copyleft, unknown, restrictive licenses)",
	}, handleLicense)

	fmt.Fprintf(os.Stderr, "ClauGuard MCP server starting (v%s)...\n", version)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("MCP server error: %w", err)
	}
	return nil
}

// handleScan runs the full scan pipeline.
func handleScan(ctx context.Context, req *mcp.CallToolRequest, args scanArgs) (*mcp.CallToolResult, any, error) {
	deps, ecosystems, err := detectAndParse(args.Path, args.IncludeDev)
	if err != nil {
		return errorResult(err.Error()), nil, nil
	}

	if len(deps) == 0 {
		return textResult("No dependencies found in " + args.Path), nil, nil
	}

	result := &models.ScanResult{
		ProjectPath:  args.Path,
		Dependencies: deps,
		Ecosystems:   ecosystems,
	}

	if !args.SkipVuln {
		vulns, err := advisory.NewOSVClient().QueryBatch(deps)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: vulnerability check failed: %v\n", err)
		} else {
			result.Vulnerabilities = vulns
		}
	}

	if !args.SkipIntegrity {
		checker := integrity.NewChecker()
		result.IntegrityIssues = checker.Check(deps)
	}

	if !args.SkipLicense {
		manifests, _ := detector.Detect(args.Path)
		result.Licenses = scanner.ExtractLicenses(manifests)
	}

	return jsonResult(result)
}

// handleIntegrity runs only supply chain integrity checks.
func handleIntegrity(ctx context.Context, req *mcp.CallToolRequest, args integrityArgs) (*mcp.CallToolResult, any, error) {
	deps, _, err := detectAndParse(args.Path, args.IncludeDev)
	if err != nil {
		return errorResult(err.Error()), nil, nil
	}

	if len(deps) == 0 {
		return textResult("No dependencies found in " + args.Path), nil, nil
	}

	checker := integrity.NewChecker()
	issues := checker.Check(deps)

	if len(issues) == 0 {
		return textResult(fmt.Sprintf("No integrity issues found across %d dependencies", len(deps))), nil, nil
	}

	return jsonResult(map[string]any{
		"dependency_count": len(deps),
		"issue_count":      len(issues),
		"issues":           issues,
	})
}

// handleVuln runs only vulnerability checks.
func handleVuln(ctx context.Context, req *mcp.CallToolRequest, args vulnArgs) (*mcp.CallToolResult, any, error) {
	deps, _, err := detectAndParse(args.Path, args.IncludeDev)
	if err != nil {
		return errorResult(err.Error()), nil, nil
	}

	if len(deps) == 0 {
		return textResult("No dependencies found in " + args.Path), nil, nil
	}

	vulns, err := advisory.NewOSVClient().QueryBatch(deps)
	if err != nil {
		return errorResult(fmt.Sprintf("vulnerability check failed: %v", err)), nil, nil
	}

	if len(vulns) == 0 {
		return textResult(fmt.Sprintf("No vulnerabilities found across %d dependencies", len(deps))), nil, nil
	}

	return jsonResult(map[string]any{
		"dependency_count":    len(deps),
		"vulnerability_count": len(vulns),
		"vulnerabilities":     vulns,
	})
}

// handleLicense runs only license compliance checks.
func handleLicense(ctx context.Context, req *mcp.CallToolRequest, args licenseArgs) (*mcp.CallToolResult, any, error) {
	deps, _, err := detectAndParse(args.Path, args.IncludeDev)
	if err != nil {
		return errorResult(err.Error()), nil, nil
	}

	if len(deps) == 0 {
		return textResult("No dependencies found in " + args.Path), nil, nil
	}

	manifests, _ := detector.Detect(args.Path)
	licenses := scanner.ExtractLicenses(manifests)

	var highRisk, unknown []models.LicenseInfo
	for _, l := range licenses {
		switch l.Risk {
		case models.LicenseRiskHigh:
			highRisk = append(highRisk, l)
		case models.LicenseRiskUnknown:
			unknown = append(unknown, l)
		}
	}

	if len(highRisk) == 0 && len(unknown) == 0 {
		return textResult(fmt.Sprintf("No license concerns across %d dependencies (%d licenses detected)", len(deps), len(licenses))), nil, nil
	}

	return jsonResult(map[string]any{
		"dependency_count": len(deps),
		"license_count":    len(licenses),
		"high_risk":        highRisk,
		"unknown":          unknown,
	})
}

// --- Helpers ---

// detectAndParse finds manifests and parses dependencies from a project path.
func detectAndParse(path string, includeDev bool) ([]models.Dependency, []models.Ecosystem, error) {
	manifests, err := detector.Detect(path)
	if err != nil {
		return nil, nil, fmt.Errorf("detection failed: %w", err)
	}

	ecosystems := detector.DetectedEcosystems(manifests)

	deps, warnings, err := scanner.ParseAll(manifests)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing failed: %w", err)
	}

	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	if !includeDev {
		var prod []models.Dependency
		for _, d := range deps {
			if !d.IsDev {
				prod = append(prod, d)
			}
		}
		deps = prod
	}

	return deps, ecosystems, nil
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}
}

func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "Error: " + msg},
		},
		IsError: true,
	}
}

func jsonResult(v any) (*mcp.CallToolResult, any, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errorResult(fmt.Sprintf("JSON encoding failed: %v", err)), nil, nil
	}

	// For large results, provide a summary + JSON
	text := string(data)
	if len(text) > 50000 {
		text = text[:50000] + "\n... (truncated)"
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}, nil, nil
}

