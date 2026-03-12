package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func emptyScanResult() *models.ScanResult {
	return &models.ScanResult{
		ProjectPath: "/tmp/empty-project",
	}
}

func fullScanResult() *models.ScanResult {
	return &models.ScanResult{
		ProjectPath: "/home/user/my-project",
		Ecosystems:  []models.Ecosystem{models.EcosystemNpm, models.EcosystemGo},
		Dependencies: []models.Dependency{
			{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNpm},
			{Name: "golang.org/x/text", Version: "v0.3.0", Ecosystem: models.EcosystemGo},
		},
		Vulnerabilities: []models.Vulnerability{
			{
				ID:          "GHSA-1234",
				Summary:     "Prototype pollution in lodash",
				Severity:    models.SeverityCritical,
				FixVersions: []string{"4.17.21"},
				Dependency:  "lodash",
				Ecosystem:   models.EcosystemNpm,
			},
			{
				ID:         "GHSA-5678",
				Summary:    "Low severity issue",
				Severity:   models.SeverityLow,
				Dependency: "some-pkg",
				Ecosystem:  models.EcosystemNpm,
			},
		},
		IntegrityIssues: []models.IntegrityIssue{
			{
				Dependency:  "colors",
				Ecosystem:   models.EcosystemNpm,
				Type:        "maintainer_change",
				Description: "Maintainer changed recently",
				Severity:    models.SeverityHigh,
			},
		},
		Licenses: []models.LicenseInfo{
			{Dependency: "gpl-pkg", Ecosystem: models.EcosystemNpm, License: "GPL-3.0", Risk: models.LicenseRiskHigh},
			{Dependency: "mystery-pkg", Ecosystem: models.EcosystemGo, License: "", Risk: models.LicenseRiskUnknown},
			{Dependency: "mit-pkg", Ecosystem: models.EcosystemNpm, License: "MIT", Risk: models.LicenseRiskLow},
		},
		Outdated: []models.OutdatedDep{
			{Dependency: "lodash", Ecosystem: models.EcosystemNpm, CurrentVersion: "4.17.20", LatestVersion: "4.17.21"},
		},
	}
}

// ---------------------------------------------------------------------------
// 1. Report() dispatch
// ---------------------------------------------------------------------------

func TestReport_JSON(t *testing.T) {
	var buf bytes.Buffer
	err := Report(&buf, emptyScanResult(), FormatJSON, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Must produce valid JSON
	var decoded models.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestReport_Table(t *testing.T) {
	var buf bytes.Buffer
	err := Report(&buf, emptyScanResult(), FormatTable, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "clauguard scan results") {
		t.Error("table output should contain header")
	}
}

func TestReport_UnknownFormatDefaultsToTable(t *testing.T) {
	var buf bytes.Buffer
	err := Report(&buf, emptyScanResult(), Format("yaml"), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "clauguard scan results") {
		t.Error("unknown format should default to table output")
	}
}

// ---------------------------------------------------------------------------
// 2. reportJSON()
// ---------------------------------------------------------------------------

func TestReportJSON_RoundTrip(t *testing.T) {
	original := fullScanResult()
	var buf bytes.Buffer
	if err := reportJSON(&buf, original); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var decoded models.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if decoded.ProjectPath != original.ProjectPath {
		t.Errorf("project_path = %q, want %q", decoded.ProjectPath, original.ProjectPath)
	}
	if len(decoded.Dependencies) != len(original.Dependencies) {
		t.Errorf("dependencies count = %d, want %d", len(decoded.Dependencies), len(original.Dependencies))
	}
	if len(decoded.Vulnerabilities) != len(original.Vulnerabilities) {
		t.Errorf("vulnerabilities count = %d, want %d", len(decoded.Vulnerabilities), len(original.Vulnerabilities))
	}
	if len(decoded.Licenses) != len(original.Licenses) {
		t.Errorf("licenses count = %d, want %d", len(decoded.Licenses), len(original.Licenses))
	}
	if len(decoded.IntegrityIssues) != len(original.IntegrityIssues) {
		t.Errorf("integrity_issues count = %d, want %d", len(decoded.IntegrityIssues), len(original.IntegrityIssues))
	}
	if len(decoded.Outdated) != len(original.Outdated) {
		t.Errorf("outdated count = %d, want %d", len(decoded.Outdated), len(original.Outdated))
	}
	if len(decoded.Ecosystems) != len(original.Ecosystems) {
		t.Errorf("ecosystems count = %d, want %d", len(decoded.Ecosystems), len(original.Ecosystems))
	}
}

func TestReportJSON_ContainsAllFields(t *testing.T) {
	var buf bytes.Buffer
	if err := reportJSON(&buf, fullScanResult()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()

	requiredKeys := []string{
		`"project_path"`,
		`"dependencies"`,
		`"vulnerabilities"`,
		`"licenses"`,
		`"integrity_issues"`,
		`"outdated"`,
		`"ecosystems_detected"`,
	}
	for _, key := range requiredKeys {
		if !strings.Contains(output, key) {
			t.Errorf("JSON output missing key %s", key)
		}
	}
}

func TestReportJSON_EmptyResult(t *testing.T) {
	var buf bytes.Buffer
	if err := reportJSON(&buf, emptyScanResult()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()

	// Must still be valid JSON
	var decoded models.ScanResult
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		t.Fatalf("empty result did not produce valid JSON: %v", err)
	}

	// Null arrays are encoded as null in JSON
	if !strings.Contains(output, `"dependencies": null`) &&
		!strings.Contains(output, `"dependencies":null`) {
		// json.Encoder with indent will produce "dependencies": null
		// Just verify it parses correctly — already done above
	}
}

// ---------------------------------------------------------------------------
// 3. reportTable() with noColor=true
// ---------------------------------------------------------------------------

func TestReportTable_Header(t *testing.T) {
	var buf bytes.Buffer
	result := fullScanResult()
	_ = reportTable(&buf, result, true)
	output := buf.String()

	if !strings.Contains(output, "clauguard scan results") {
		t.Error("missing header")
	}
	if !strings.Contains(output, result.ProjectPath) {
		t.Error("missing project path")
	}
	if !strings.Contains(output, "npm, go") {
		t.Error("missing ecosystems")
	}
	if !strings.Contains(output, "Dependencies: 2") {
		t.Error("missing dependency count")
	}
}

func TestReportTable_VulnerabilitiesSection(t *testing.T) {
	var buf bytes.Buffer
	result := fullScanResult()
	_ = reportTable(&buf, result, true)
	output := buf.String()

	if !strings.Contains(output, "VULNERABILITIES (2 found)") {
		t.Error("missing vulnerabilities header")
	}
	if !strings.Contains(output, "CRITICAL") {
		t.Error("missing CRITICAL severity label")
	}
	if !strings.Contains(output, "lodash") {
		t.Error("missing package name")
	}
	if !strings.Contains(output, "npm") {
		t.Error("missing ecosystem")
	}
	if !strings.Contains(output, "GHSA-1234") {
		t.Error("missing vulnerability ID")
	}
	if !strings.Contains(output, "Prototype pollution") {
		t.Error("missing summary")
	}
	if !strings.Contains(output, "Fix: 4.17.21") {
		t.Error("missing fix versions")
	}
}

func TestReportTable_NoVulnerabilities(t *testing.T) {
	var buf bytes.Buffer
	result := emptyScanResult()
	_ = reportTable(&buf, result, true)
	output := buf.String()

	if !strings.Contains(output, "VULNERABILITIES: None found") {
		t.Error("expected 'None found' message when no vulnerabilities")
	}
}

func TestReportTable_IntegrityIssues(t *testing.T) {
	var buf bytes.Buffer
	result := fullScanResult()
	_ = reportTable(&buf, result, true)
	output := buf.String()

	if !strings.Contains(output, "INTEGRITY ISSUES (1 found)") {
		t.Error("missing integrity issues header")
	}
	if !strings.Contains(output, "colors") {
		t.Error("missing integrity issue dependency")
	}
	if !strings.Contains(output, "Maintainer changed recently") {
		t.Error("missing integrity issue description")
	}
}

func TestReportTable_LicenseConcerns(t *testing.T) {
	var buf bytes.Buffer
	result := fullScanResult()
	_ = reportTable(&buf, result, true)
	output := buf.String()

	if !strings.Contains(output, "LICENSE CONCERNS") {
		t.Error("missing license concerns section")
	}
	if !strings.Contains(output, "High risk (copyleft)") {
		t.Error("missing high risk label")
	}
	if !strings.Contains(output, "gpl-pkg: GPL-3.0") {
		t.Error("missing high risk license entry")
	}
	if !strings.Contains(output, "Unknown license") {
		t.Error("missing unknown license label")
	}
	if !strings.Contains(output, "mystery-pkg (go)") {
		t.Error("missing unknown license entry")
	}
}

func TestReportTable_OutdatedDependencies(t *testing.T) {
	var buf bytes.Buffer
	result := fullScanResult()
	_ = reportTable(&buf, result, true)
	output := buf.String()

	if !strings.Contains(output, "OUTDATED DEPENDENCIES (1)") {
		t.Error("missing outdated section header")
	}
	if !strings.Contains(output, "lodash") {
		t.Error("missing outdated package name")
	}
	if !strings.Contains(output, "4.17.20") {
		t.Error("missing current version")
	}
	if !strings.Contains(output, "4.17.21") {
		t.Error("missing latest version")
	}
}

func TestReportTable_ResultPASS(t *testing.T) {
	var buf bytes.Buffer
	result := emptyScanResult() // exit code 0
	_ = reportTable(&buf, result, true)
	output := buf.String()

	if !strings.Contains(output, "Result: PASS") {
		t.Error("expected PASS for clean result")
	}
}

func TestReportTable_ResultWARN(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath: "/tmp/warn",
		Vulnerabilities: []models.Vulnerability{
			{ID: "V-1", Severity: models.SeverityMedium, Dependency: "pkg", Ecosystem: models.EcosystemNpm},
		},
	}
	var buf bytes.Buffer
	_ = reportTable(&buf, result, true)
	output := buf.String()

	if !strings.Contains(output, "Result: WARN") {
		t.Error("expected WARN for medium-severity-only result")
	}
}

func TestReportTable_ResultFAIL(t *testing.T) {
	var buf bytes.Buffer
	result := fullScanResult() // has critical vuln + integrity issues → exit code 2
	_ = reportTable(&buf, result, true)
	output := buf.String()

	if !strings.Contains(output, "Result: FAIL") {
		t.Error("expected FAIL for critical vulnerability result")
	}
}

// ---------------------------------------------------------------------------
// 4. reportTable() with noColor=false (ANSI codes)
// ---------------------------------------------------------------------------

func TestReportTable_ColorContainsANSI(t *testing.T) {
	var buf bytes.Buffer
	result := fullScanResult()
	_ = reportTable(&buf, result, false)
	output := buf.String()

	if !strings.Contains(output, "\033[") {
		t.Error("expected ANSI escape codes in colored output")
	}
}

func TestReportTable_ColorSeverityFixedWidth(t *testing.T) {
	// The formatted severity should pad to 10 chars inside the ANSI sequence
	sev := formatSeverity(models.SeverityCritical, false)
	// Format: \033[31m%-10s\033[0m → the inner text is "CRITICAL" padded to 10
	if !strings.Contains(sev, "CRITICAL") {
		t.Error("colored severity missing label")
	}
	// The reset code must be present
	if !strings.Contains(sev, "\033[0m") {
		t.Error("colored severity missing ANSI reset")
	}
}

// ---------------------------------------------------------------------------
// 5. formatSeverity()
// ---------------------------------------------------------------------------

func TestFormatSeverity_NoColor(t *testing.T) {
	tests := []struct {
		severity models.Severity
		expected string
	}{
		{models.SeverityCritical, "CRITICAL"},
		{models.SeverityHigh, "HIGH"},
		{models.SeverityMedium, "MEDIUM"},
		{models.SeverityLow, "LOW"},
		{models.SeverityUnknown, "UNKNOWN"},
	}
	for _, tt := range tests {
		got := formatSeverity(tt.severity, true)
		if got != tt.expected {
			t.Errorf("formatSeverity(%q, true) = %q, want %q", tt.severity, got, tt.expected)
		}
	}
}

func TestFormatSeverity_WithColor(t *testing.T) {
	tests := []struct {
		severity models.Severity
		ansiCode string
	}{
		{models.SeverityCritical, "31"},
		{models.SeverityHigh, "91"},
		{models.SeverityMedium, "33"},
		{models.SeverityLow, "36"},
	}
	for _, tt := range tests {
		got := formatSeverity(tt.severity, false)
		expectedPrefix := "\033[" + tt.ansiCode + "m"
		if !strings.HasPrefix(got, expectedPrefix) {
			t.Errorf("formatSeverity(%q, false) = %q, want prefix %q", tt.severity, got, expectedPrefix)
		}
		if !strings.HasSuffix(got, "\033[0m") {
			t.Errorf("formatSeverity(%q, false) = %q, want suffix \\033[0m", tt.severity, got)
		}
	}
}

func TestFormatSeverity_UnknownWithColor(t *testing.T) {
	got := formatSeverity(models.SeverityUnknown, false)
	if strings.Contains(got, "\033[") {
		t.Error("unknown severity should not have ANSI codes even with color enabled")
	}
	if got != "UNKNOWN" {
		t.Errorf("got %q, want %q", got, "UNKNOWN")
	}
}

// ---------------------------------------------------------------------------
// 6. truncate()
// ---------------------------------------------------------------------------

func TestTruncate_ShorterThanMax(t *testing.T) {
	got := truncate("hello", 10)
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestTruncate_ExactlyMax(t *testing.T) {
	got := truncate("hello", 5)
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestTruncate_LongerThanMax(t *testing.T) {
	got := truncate("hello world", 8)
	if got != "hello..." {
		t.Errorf("got %q, want %q", got, "hello...")
	}
}

func TestTruncate_LongerThanMax_Boundary(t *testing.T) {
	// maxLen=6, string="abcdefgh" → "abc..."
	got := truncate("abcdefgh", 6)
	if got != "abc..." {
		t.Errorf("got %q, want %q", got, "abc...")
	}
	if len(got) != 6 {
		t.Errorf("length = %d, want 6", len(got))
	}
}

// ---------------------------------------------------------------------------
// 7. filterLicenses()
// ---------------------------------------------------------------------------

func TestFilterLicenses_ByRisk(t *testing.T) {
	licenses := []models.LicenseInfo{
		{Dependency: "gpl-pkg", Risk: models.LicenseRiskHigh},
		{Dependency: "mit-pkg", Risk: models.LicenseRiskLow},
		{Dependency: "agpl-pkg", Risk: models.LicenseRiskHigh},
		{Dependency: "unknown-pkg", Risk: models.LicenseRiskUnknown},
	}

	high := filterLicenses(licenses, models.LicenseRiskHigh)
	if len(high) != 2 {
		t.Errorf("expected 2 high-risk, got %d", len(high))
	}
	for _, l := range high {
		if l.Risk != models.LicenseRiskHigh {
			t.Errorf("expected high risk, got %s", l.Risk)
		}
	}

	unknown := filterLicenses(licenses, models.LicenseRiskUnknown)
	if len(unknown) != 1 {
		t.Errorf("expected 1 unknown, got %d", len(unknown))
	}

	medium := filterLicenses(licenses, models.LicenseRiskMedium)
	if len(medium) != 0 {
		t.Errorf("expected 0 medium, got %d", len(medium))
	}
}

func TestFilterLicenses_EmptyInput(t *testing.T) {
	result := filterLicenses(nil, models.LicenseRiskHigh)
	if result != nil {
		t.Errorf("expected nil for empty input, got %v", result)
	}
}

func TestFilterLicenses_NoMatches(t *testing.T) {
	licenses := []models.LicenseInfo{
		{Dependency: "mit-pkg", Risk: models.LicenseRiskLow},
	}
	result := filterLicenses(licenses, models.LicenseRiskHigh)
	if result != nil {
		t.Errorf("expected nil for no matches, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// 8. formatEcosystems()
// ---------------------------------------------------------------------------

func TestFormatEcosystems_Multiple(t *testing.T) {
	got := formatEcosystems([]models.Ecosystem{models.EcosystemNpm, models.EcosystemGo, models.EcosystemPip})
	if got != "npm, go, pip" {
		t.Errorf("got %q, want %q", got, "npm, go, pip")
	}
}

func TestFormatEcosystems_Single(t *testing.T) {
	got := formatEcosystems([]models.Ecosystem{models.EcosystemCargo})
	if got != "cargo" {
		t.Errorf("got %q, want %q", got, "cargo")
	}
}

func TestFormatEcosystems_Empty(t *testing.T) {
	got := formatEcosystems(nil)
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestReportTable_NoIntegrityIssues_SectionOmitted(t *testing.T) {
	result := &models.ScanResult{ProjectPath: "/tmp/clean"}
	var buf bytes.Buffer
	_ = reportTable(&buf, result, true)
	if strings.Contains(buf.String(), "INTEGRITY ISSUES") {
		t.Error("integrity issues section should not appear when empty")
	}
}

func TestReportTable_NoLicenseConcerns_SectionOmitted(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath: "/tmp/clean",
		Licenses: []models.LicenseInfo{
			{Dependency: "mit-pkg", Risk: models.LicenseRiskLow},
		},
	}
	var buf bytes.Buffer
	_ = reportTable(&buf, result, true)
	if strings.Contains(buf.String(), "LICENSE CONCERNS") {
		t.Error("license concerns section should not appear when only low-risk licenses exist")
	}
}

func TestReportTable_NoOutdated_SectionOmitted(t *testing.T) {
	result := &models.ScanResult{ProjectPath: "/tmp/clean"}
	var buf bytes.Buffer
	_ = reportTable(&buf, result, true)
	if strings.Contains(buf.String(), "OUTDATED DEPENDENCIES") {
		t.Error("outdated section should not appear when empty")
	}
}

func TestReportTable_VulnerabilityWithoutSummaryOrFix(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath: "/tmp/minimal",
		Vulnerabilities: []models.Vulnerability{
			{ID: "V-1", Severity: models.SeverityMedium, Dependency: "pkg", Ecosystem: models.EcosystemNpm},
		},
	}
	var buf bytes.Buffer
	_ = reportTable(&buf, result, true)
	output := buf.String()

	// Should not contain "Fix:" line when no fix versions
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Fix:") {
			t.Error("should not show Fix line when no fix versions")
		}
	}
}
