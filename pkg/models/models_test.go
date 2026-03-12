package models

import "testing"

func TestExitCode(t *testing.T) {
	tests := []struct {
		name     string
		result   ScanResult
		expected int
	}{
		{
			name:     "no issues returns 0",
			result:   ScanResult{},
			expected: 0,
		},
		{
			name: "nil slices returns 0",
			result: ScanResult{
				Vulnerabilities: nil,
				IntegrityIssues: nil,
			},
			expected: 0,
		},
		{
			name: "empty slices returns 0",
			result: ScanResult{
				Vulnerabilities: []Vulnerability{},
				IntegrityIssues: []IntegrityIssue{},
			},
			expected: 0,
		},
		{
			name: "critical vulnerability returns 2",
			result: ScanResult{
				Vulnerabilities: []Vulnerability{
					{ID: "CVE-2024-0001", Severity: SeverityCritical, Dependency: "foo"},
				},
			},
			expected: 2,
		},
		{
			name: "high vulnerability returns 2",
			result: ScanResult{
				Vulnerabilities: []Vulnerability{
					{ID: "CVE-2024-0002", Severity: SeverityHigh, Dependency: "bar"},
				},
			},
			expected: 2,
		},
		{
			name: "medium vulnerability only returns 1",
			result: ScanResult{
				Vulnerabilities: []Vulnerability{
					{ID: "CVE-2024-0003", Severity: SeverityMedium, Dependency: "baz"},
				},
			},
			expected: 1,
		},
		{
			name: "low vulnerability only returns 1",
			result: ScanResult{
				Vulnerabilities: []Vulnerability{
					{ID: "CVE-2024-0004", Severity: SeverityLow, Dependency: "qux"},
				},
			},
			expected: 1,
		},
		{
			name: "unknown severity vulnerability only returns 1",
			result: ScanResult{
				Vulnerabilities: []Vulnerability{
					{ID: "CVE-2024-0005", Severity: SeverityUnknown, Dependency: "quux"},
				},
			},
			expected: 1,
		},
		{
			name: "integrity issue with no vulnerabilities returns 2",
			result: ScanResult{
				IntegrityIssues: []IntegrityIssue{
					{Dependency: "evil-pkg", Type: "typosquat", Severity: SeverityLow},
				},
			},
			expected: 2,
		},
		{
			name: "integrity issue with medium vulnerability returns 2",
			result: ScanResult{
				Vulnerabilities: []Vulnerability{
					{ID: "CVE-2024-0006", Severity: SeverityMedium, Dependency: "dep"},
				},
				IntegrityIssues: []IntegrityIssue{
					{Dependency: "shady-pkg", Type: "maintainer_change"},
				},
			},
			expected: 2,
		},
		{
			name: "critical vulnerability takes precedence over integrity check",
			result: ScanResult{
				Vulnerabilities: []Vulnerability{
					{ID: "CVE-2024-0007", Severity: SeverityCritical, Dependency: "dep"},
				},
				IntegrityIssues: []IntegrityIssue{
					{Dependency: "shady-pkg", Type: "typosquat"},
				},
			},
			expected: 2,
		},
		{
			name: "mix of severities with critical returns 2",
			result: ScanResult{
				Vulnerabilities: []Vulnerability{
					{ID: "CVE-2024-0010", Severity: SeverityLow, Dependency: "a"},
					{ID: "CVE-2024-0011", Severity: SeverityMedium, Dependency: "b"},
					{ID: "CVE-2024-0012", Severity: SeverityCritical, Dependency: "c"},
				},
			},
			expected: 2,
		},
		{
			name: "mix of severities with high returns 2",
			result: ScanResult{
				Vulnerabilities: []Vulnerability{
					{ID: "CVE-2024-0013", Severity: SeverityLow, Dependency: "a"},
					{ID: "CVE-2024-0014", Severity: SeverityMedium, Dependency: "b"},
					{ID: "CVE-2024-0015", Severity: SeverityHigh, Dependency: "c"},
				},
			},
			expected: 2,
		},
		{
			name: "mix of medium and low only returns 1",
			result: ScanResult{
				Vulnerabilities: []Vulnerability{
					{ID: "CVE-2024-0016", Severity: SeverityLow, Dependency: "a"},
					{ID: "CVE-2024-0017", Severity: SeverityMedium, Dependency: "b"},
					{ID: "CVE-2024-0018", Severity: SeverityLow, Dependency: "c"},
				},
			},
			expected: 1,
		},
		{
			name: "multiple integrity issues returns 2",
			result: ScanResult{
				IntegrityIssues: []IntegrityIssue{
					{Dependency: "a", Type: "typosquat"},
					{Dependency: "b", Type: "unpublished_source"},
				},
			},
			expected: 2,
		},
		{
			name: "outdated deps and licenses alone return 0",
			result: ScanResult{
				Licenses: []LicenseInfo{
					{Dependency: "lib", License: "MIT", Risk: LicenseRiskLow},
				},
				Outdated: []OutdatedDep{
					{Dependency: "old-lib", CurrentVersion: "1.0.0", LatestVersion: "2.0.0"},
				},
			},
			expected: 0,
		},
		{
			name: "high severity vulnerability found later in slice returns 2",
			result: ScanResult{
				Vulnerabilities: []Vulnerability{
					{ID: "CVE-1", Severity: SeverityLow, Dependency: "a"},
					{ID: "CVE-2", Severity: SeverityLow, Dependency: "b"},
					{ID: "CVE-3", Severity: SeverityLow, Dependency: "c"},
					{ID: "CVE-4", Severity: SeverityHigh, Dependency: "d"},
				},
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.result.ExitCode()
			if got != tt.expected {
				t.Errorf("ExitCode() = %d, want %d", got, tt.expected)
			}
		})
	}
}
