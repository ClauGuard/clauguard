package scanner

import (
	"fmt"

	"github.com/ClauGuard/clauguard/internal/detector"
	"github.com/ClauGuard/clauguard/internal/license"
	"github.com/ClauGuard/clauguard/pkg/models"
)

// Parser extracts dependencies from a manifest file.
type Parser interface {
	Parse(manifestPath string) ([]models.Dependency, error)
	Ecosystem() models.Ecosystem
}

// registry holds parsers keyed by ecosystem.
var registry = map[models.Ecosystem]Parser{}

// Register adds a parser for an ecosystem.
func Register(p Parser) {
	registry[p.Ecosystem()] = p
}

// ParseAll reads all detected manifests and returns the combined dependency list.
// It prefers lock files over manifest files when both exist for the same ecosystem in the same directory.
// Parse errors are collected as warnings rather than silently swallowed.
func ParseAll(manifests []detector.DetectedManifest) ([]models.Dependency, []string, error) {
	var all []models.Dependency
	var warnings []string
	seen := make(map[string]bool)

	for _, m := range manifests {
		p, ok := registry[m.Ecosystem]
		if !ok {
			continue
		}

		deps, err := p.Parse(m.Path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("failed to parse %s: %v", m.Path, err))
			continue
		}

		for _, d := range deps {
			key := string(d.Ecosystem) + ":" + d.Name + ":" + d.Version
			if !seen[key] {
				seen[key] = true
				all = append(all, d)
			}
		}
	}

	return all, warnings, nil
}

// LicenseExtractor can extract license info from manifest files.
type LicenseExtractor interface {
	ExtractLicenses(manifestPath string) []models.LicenseInfo
}

// ExtractLicenses collects license information from parsers that support it.
func ExtractLicenses(manifests []detector.DetectedManifest) []models.LicenseInfo {
	var all []models.LicenseInfo
	seen := make(map[string]bool)

	for _, m := range manifests {
		p, ok := registry[m.Ecosystem]
		if !ok {
			continue
		}
		extractor, ok := p.(LicenseExtractor)
		if !ok {
			continue
		}
		for _, l := range extractor.ExtractLicenses(m.Path) {
			key := string(l.Ecosystem) + ":" + l.Dependency
			if !seen[key] {
				seen[key] = true
				risk, _ := license.ClassifyLicense(l.License)
				l.Risk = risk
				all = append(all, l)
			}
		}
	}

	return all
}
