package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ClauGuard/clauguard/pkg/models"
)

// Format represents the output format.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
)

// Report writes the scan results in the specified format.
func Report(w io.Writer, result *models.ScanResult, format Format, noColor bool) error {
	switch format {
	case FormatJSON:
		return reportJSON(w, result)
	default:
		return reportTable(w, result, noColor)
	}
}

func reportJSON(w io.Writer, result *models.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func reportTable(w io.Writer, result *models.ScanResult, noColor bool) error {
	// Header
	fmt.Fprintf(w, "\n%s clauguard scan results %s\n", strings.Repeat("─", 20), strings.Repeat("─", 20))
	fmt.Fprintf(w, "Project: %s\n", result.ProjectPath)
	fmt.Fprintf(w, "Ecosystems: %s\n", formatEcosystems(result.Ecosystems))
	fmt.Fprintf(w, "Dependencies: %d\n\n", len(result.Dependencies))

	// Vulnerabilities
	if len(result.Vulnerabilities) > 0 {
		fmt.Fprintf(w, "VULNERABILITIES (%d found)\n", len(result.Vulnerabilities))
		fmt.Fprintf(w, "%s\n", strings.Repeat("─", 80))
		fmt.Fprintf(w, "  %-10s  %-30s  %-10s  %s\n", "SEVERITY", "PACKAGE", "ECOSYSTEM", "ID")
		fmt.Fprintf(w, "%s\n", strings.Repeat("─", 80))

		for _, v := range result.Vulnerabilities {
			sev := formatSeverity(v.Severity, noColor)
			fmt.Fprintf(w, "  %-10s  %-30s  %-10s  %s\n", sev, truncate(v.Dependency, 30), v.Ecosystem, v.ID)
			if v.Summary != "" {
				fmt.Fprintf(w, "  %s%s\n", strings.Repeat(" ", 12), truncate(v.Summary, 65))
			}
			if len(v.FixVersions) > 0 {
				fmt.Fprintf(w, "  %sFix: %s\n", strings.Repeat(" ", 12), strings.Join(v.FixVersions, ", "))
			}
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintf(w, "VULNERABILITIES: None found\n\n")
	}

	// Integrity issues
	if len(result.IntegrityIssues) > 0 {
		fmt.Fprintf(w, "INTEGRITY ISSUES (%d found)\n", len(result.IntegrityIssues))
		fmt.Fprintf(w, "%s\n", strings.Repeat("─", 80))
		for _, issue := range result.IntegrityIssues {
			fmt.Fprintf(w, "  [%s] %s (%s): %s\n", issue.Severity, issue.Dependency, issue.Ecosystem, issue.Description)
		}
		fmt.Fprintln(w)
	}

	// License issues
	highRiskLicenses := filterLicenses(result.Licenses, models.LicenseRiskHigh)
	unknownLicenses := filterLicenses(result.Licenses, models.LicenseRiskUnknown)

	if len(highRiskLicenses) > 0 || len(unknownLicenses) > 0 {
		fmt.Fprintf(w, "LICENSE CONCERNS\n")
		fmt.Fprintf(w, "%s\n", strings.Repeat("─", 80))

		if len(highRiskLicenses) > 0 {
			fmt.Fprintf(w, "  High risk (copyleft):\n")
			for _, l := range highRiskLicenses {
				fmt.Fprintf(w, "    - %s: %s\n", l.Dependency, l.License)
			}
		}
		if len(unknownLicenses) > 0 {
			fmt.Fprintf(w, "  Unknown license:\n")
			for _, l := range unknownLicenses {
				fmt.Fprintf(w, "    - %s (%s)\n", l.Dependency, l.Ecosystem)
			}
		}
		fmt.Fprintln(w)
	}

	// Outdated deps
	if len(result.Outdated) > 0 {
		fmt.Fprintf(w, "OUTDATED DEPENDENCIES (%d)\n", len(result.Outdated))
		fmt.Fprintf(w, "%s\n", strings.Repeat("─", 80))
		fmt.Fprintf(w, "  %-30s  %-15s  %-15s  %s\n", "PACKAGE", "CURRENT", "LATEST", "ECOSYSTEM")
		fmt.Fprintf(w, "%s\n", strings.Repeat("─", 80))
		for _, o := range result.Outdated {
			fmt.Fprintf(w, "  %-30s  %-15s  %-15s  %s\n", truncate(o.Dependency, 30), o.CurrentVersion, o.LatestVersion, o.Ecosystem)
		}
		fmt.Fprintln(w)
	}

	// Summary line
	fmt.Fprintf(w, "%s\n", strings.Repeat("─", 80))
	exitCode := result.ExitCode()
	if exitCode == 0 {
		fmt.Fprintf(w, "Result: PASS — no critical issues found\n")
	} else if exitCode == 1 {
		fmt.Fprintf(w, "Result: WARN — non-critical issues found\n")
	} else {
		fmt.Fprintf(w, "Result: FAIL — critical issues found\n")
	}

	return nil
}

// formatSeverity returns the severity label, with ANSI color unless disabled.
// Uses fixed-width plain text so column alignment isn't broken by escape codes.
func formatSeverity(s models.Severity, noColor bool) string {
	label := strings.ToUpper(string(s))
	if noColor {
		return label
	}

	var code string
	switch s {
	case models.SeverityCritical:
		code = "31" // red
	case models.SeverityHigh:
		code = "91" // bright red
	case models.SeverityMedium:
		code = "33" // yellow
	case models.SeverityLow:
		code = "36" // cyan
	default:
		return label
	}
	return fmt.Sprintf("\033[%sm%-10s\033[0m", code, label)
}

func formatEcosystems(ecosystems []models.Ecosystem) string {
	var names []string
	for _, e := range ecosystems {
		names = append(names, string(e))
	}
	return strings.Join(names, ", ")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func filterLicenses(licenses []models.LicenseInfo, risk models.LicenseRisk) []models.LicenseInfo {
	var result []models.LicenseInfo
	for _, l := range licenses {
		if l.Risk == risk {
			result = append(result, l)
		}
	}
	return result
}
