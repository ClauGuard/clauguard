package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClauGuard/clauguard/internal/detector"
	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestParseAll_CombinesMultipleManifests(t *testing.T) {
	dir := t.TempDir()

	// Create a package.json
	pkgJSON := `{"dependencies": {"express": "^4.18.0"}}`
	writeTempFile(t, dir, "package.json", pkgJSON)

	// Create a composer.json
	composerJSON := `{"require": {"monolog/monolog": "^3.0"}}`
	writeTempFile(t, dir, "composer.json", composerJSON)

	manifests := []detector.DetectedManifest{
		{Path: filepath.Join(dir, "package.json"), Ecosystem: models.EcosystemNpm},
		{Path: filepath.Join(dir, "composer.json"), Ecosystem: models.EcosystemComposer},
	}

	deps, warnings, err := ParseAll(manifests)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}

	ecosystems := map[models.Ecosystem]bool{}
	for _, d := range deps {
		ecosystems[d.Ecosystem] = true
	}
	if !ecosystems[models.EcosystemNpm] || !ecosystems[models.EcosystemComposer] {
		t.Errorf("expected npm and composer ecosystems, got %v", ecosystems)
	}
}

func TestParseAll_DeduplicatesDependencies(t *testing.T) {
	dir := t.TempDir()

	pkgJSON := `{"dependencies": {"lodash": "^4.17.21"}, "devDependencies": {}}`
	writeTempFile(t, dir, "package.json", pkgJSON)

	// Same manifest passed twice — deps should be deduped
	manifests := []detector.DetectedManifest{
		{Path: filepath.Join(dir, "package.json"), Ecosystem: models.EcosystemNpm},
		{Path: filepath.Join(dir, "package.json"), Ecosystem: models.EcosystemNpm},
	}

	deps, _, err := ParseAll(manifests)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Errorf("expected 1 dep after dedup, got %d", len(deps))
	}
}

func TestParseAll_SkipsUnknownEcosystem(t *testing.T) {
	manifests := []detector.DetectedManifest{
		{Path: "/fake/path/build.gradle", Ecosystem: models.EcosystemGradle},
	}

	deps, warnings, err := ParseAll(manifests)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for skipped ecosystem, got %v", warnings)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestParseAll_CollectsWarningsOnParseError(t *testing.T) {
	dir := t.TempDir()

	// Write invalid JSON
	writeTempFile(t, dir, "package.json", "NOT JSON")

	manifests := []detector.DetectedManifest{
		{Path: filepath.Join(dir, "package.json"), Ecosystem: models.EcosystemNpm},
	}

	deps, warnings, err := ParseAll(manifests)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps on error, got %d", len(deps))
	}
}

func TestParseAll_CollectsWarningOnMissingFile(t *testing.T) {
	manifests := []detector.DetectedManifest{
		{Path: "/nonexistent/package.json", Ecosystem: models.EcosystemNpm},
	}

	deps, warnings, err := ParseAll(manifests)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning for missing file, got %d", len(warnings))
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestParseAll_EmptyInput(t *testing.T) {
	deps, warnings, err := ParseAll(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 || len(warnings) != 0 {
		t.Errorf("expected empty results, got deps=%d warnings=%d", len(deps), len(warnings))
	}
}

func TestExtractLicenses_FromComposerLock(t *testing.T) {
	dir := t.TempDir()

	lockContent := `{
		"packages": [
			{"name": "monolog/monolog", "version": "3.5.0", "license": ["MIT"]},
			{"name": "some/gpl-pkg", "version": "1.0.0", "license": ["GPL-3.0"]}
		],
		"packages-dev": [
			{"name": "phpunit/phpunit", "version": "10.0.0", "license": ["BSD-3-Clause"]}
		]
	}`
	writeTempFile(t, dir, "composer.lock", lockContent)

	manifests := []detector.DetectedManifest{
		{Path: filepath.Join(dir, "composer.lock"), Ecosystem: models.EcosystemComposer},
	}

	licenses := ExtractLicenses(manifests)
	if len(licenses) != 3 {
		t.Fatalf("expected 3 license entries, got %d", len(licenses))
	}

	licMap := map[string]models.LicenseInfo{}
	for _, l := range licenses {
		licMap[l.Dependency] = l
	}

	// MIT should be low risk
	if licMap["monolog/monolog"].Risk != models.LicenseRiskLow {
		t.Errorf("expected MIT to be low risk, got %s", licMap["monolog/monolog"].Risk)
	}
	// GPL should be high risk
	if licMap["some/gpl-pkg"].Risk != models.LicenseRiskHigh {
		t.Errorf("expected GPL to be high risk, got %s", licMap["some/gpl-pkg"].Risk)
	}
	// BSD should be low risk
	if licMap["phpunit/phpunit"].Risk != models.LicenseRiskLow {
		t.Errorf("expected BSD to be low risk, got %s", licMap["phpunit/phpunit"].Risk)
	}
}

func TestExtractLicenses_DeduplicatesByEcosystemAndDep(t *testing.T) {
	dir := t.TempDir()

	lockContent := `{
		"packages": [
			{"name": "vendor/pkg", "version": "1.0.0", "license": ["MIT"]}
		],
		"packages-dev": []
	}`
	writeTempFile(t, dir, "composer.lock", lockContent)

	manifests := []detector.DetectedManifest{
		{Path: filepath.Join(dir, "composer.lock"), Ecosystem: models.EcosystemComposer},
		{Path: filepath.Join(dir, "composer.lock"), Ecosystem: models.EcosystemComposer},
	}

	licenses := ExtractLicenses(manifests)
	if len(licenses) != 1 {
		t.Errorf("expected 1 deduped license, got %d", len(licenses))
	}
}

func TestExtractLicenses_SkipsNonExtractorParsers(t *testing.T) {
	dir := t.TempDir()

	// NpmParser does not implement LicenseExtractor
	writeTempFile(t, dir, "package.json", `{"dependencies": {"express": "^4.0.0"}}`)

	manifests := []detector.DetectedManifest{
		{Path: filepath.Join(dir, "package.json"), Ecosystem: models.EcosystemNpm},
	}

	licenses := ExtractLicenses(manifests)
	if len(licenses) != 0 {
		t.Errorf("expected 0 licenses from npm parser, got %d", len(licenses))
	}
}

func TestExtractLicenses_SkipsUnknownEcosystem(t *testing.T) {
	manifests := []detector.DetectedManifest{
		{Path: "/fake/build.gradle", Ecosystem: models.EcosystemGradle},
	}
	licenses := ExtractLicenses(manifests)
	if len(licenses) != 0 {
		t.Errorf("expected 0 licenses, got %d", len(licenses))
	}
}

func writeTempFile(t *testing.T, dir, name, content string) {
	t.Helper()
	err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write temp file %s: %v", name, err)
	}
}
