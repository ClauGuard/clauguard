package models

// Ecosystem represents a package ecosystem (npm, composer, pip, go, cargo, gem, etc.)
type Ecosystem string

const (
	EcosystemNpm      Ecosystem = "npm"
	EcosystemComposer Ecosystem = "composer"
	EcosystemPip      Ecosystem = "pip"
	EcosystemGo       Ecosystem = "go"
	EcosystemCargo    Ecosystem = "cargo"
	EcosystemGem      Ecosystem = "gem"
	EcosystemMaven    Ecosystem = "maven"
	EcosystemGradle   Ecosystem = "gradle"
	EcosystemNuget    Ecosystem = "nuget"
	EcosystemSwift    Ecosystem = "swift"
	EcosystemCocoaPod Ecosystem = "cocoapods"
	EcosystemPub      Ecosystem = "pub"
)

// Dependency represents a single project dependency.
type Dependency struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Ecosystem Ecosystem `json:"ecosystem"`
	Source    string    `json:"source"`
	IsDev     bool      `json:"is_dev"`
}

// Severity levels for vulnerabilities.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityUnknown  Severity = "unknown"
)

// Vulnerability represents a known security vulnerability in a dependency.
type Vulnerability struct {
	ID          string   `json:"id"`
	Aliases     []string `json:"aliases,omitempty"`
	Summary     string   `json:"summary"`
	Details     string   `json:"details,omitempty"`
	Severity    Severity `json:"severity"`
	FixVersions []string `json:"fix_versions,omitempty"`
	References  []string `json:"references,omitempty"`
	Dependency  string   `json:"dependency"`
	Ecosystem   Ecosystem `json:"ecosystem"`
}

// LicenseRisk represents the risk level of a license.
type LicenseRisk string

const (
	LicenseRiskHigh    LicenseRisk = "high"    // copyleft, viral (GPL, AGPL)
	LicenseRiskMedium  LicenseRisk = "medium"  // weak copyleft (LGPL, MPL)
	LicenseRiskLow     LicenseRisk = "low"     // permissive (MIT, Apache, BSD)
	LicenseRiskUnknown LicenseRisk = "unknown" // undetected or unrecognized
)

// LicenseInfo represents license information for a dependency.
type LicenseInfo struct {
	Dependency string      `json:"dependency"`
	Ecosystem  Ecosystem   `json:"ecosystem"`
	License    string      `json:"license"`
	Risk       LicenseRisk `json:"risk"`
	SPDX       string      `json:"spdx,omitempty"`
}

// IntegrityIssue represents a supply chain integrity concern.
type IntegrityIssue struct {
	Dependency  string    `json:"dependency"`
	Ecosystem   Ecosystem `json:"ecosystem"`
	Type        string    `json:"type"` // e.g., "typosquat", "maintainer_change", "unpublished_source"
	Description string    `json:"description"`
	Severity    Severity  `json:"severity"`
}

// ScanResult holds the complete results of scanning a project.
type ScanResult struct {
	ProjectPath     string           `json:"project_path"`
	Dependencies    []Dependency     `json:"dependencies"`
	Vulnerabilities []Vulnerability  `json:"vulnerabilities"`
	Licenses        []LicenseInfo    `json:"licenses"`
	IntegrityIssues []IntegrityIssue `json:"integrity_issues"`
	Outdated        []OutdatedDep    `json:"outdated"`
	Ecosystems      []Ecosystem      `json:"ecosystems_detected"`
}

// OutdatedDep represents a dependency that has a newer version available.
type OutdatedDep struct {
	Dependency     string    `json:"dependency"`
	Ecosystem      Ecosystem `json:"ecosystem"`
	CurrentVersion string    `json:"current_version"`
	LatestVersion  string    `json:"latest_version"`
}

// ExitCode returns the appropriate exit code based on scan results.
func (r *ScanResult) ExitCode() int {
	for _, v := range r.Vulnerabilities {
		if v.Severity == SeverityCritical || v.Severity == SeverityHigh {
			return 2
		}
	}
	if len(r.IntegrityIssues) > 0 {
		return 2
	}
	if len(r.Vulnerabilities) > 0 {
		return 1
	}
	return 0
}
