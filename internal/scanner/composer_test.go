package scanner

import (
	"path/filepath"
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestComposerParser_Ecosystem(t *testing.T) {
	p := &ComposerParser{}
	if p.Ecosystem() != models.EcosystemComposer {
		t.Errorf("expected composer, got %s", p.Ecosystem())
	}
}

func TestComposerParser_ComposerJSON_RequireAndRequireDev(t *testing.T) {
	dir := t.TempDir()
	content := `{
		"require": {
			"php": "^8.2",
			"ext-json": "*",
			"monolog/monolog": "^3.0",
			"symfony/console": "^7.0"
		},
		"require-dev": {
			"phpunit/phpunit": "^10.0"
		}
	}`
	writeTempFile(t, dir, "composer.json", content)

	p := &ComposerParser{}
	deps, err := p.Parse(filepath.Join(dir, "composer.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// php and ext-json should be filtered out => 2 prod + 1 dev = 3
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps (php/ext filtered), got %d", len(deps))
	}

	depMap := map[string]models.Dependency{}
	for _, d := range deps {
		depMap[d.Name] = d
	}

	if _, ok := depMap["php"]; ok {
		t.Error("php should be filtered out")
	}
	if _, ok := depMap["ext-json"]; ok {
		t.Error("ext-json should be filtered out")
	}
	if d, ok := depMap["monolog/monolog"]; !ok {
		t.Error("missing monolog/monolog")
	} else if d.IsDev {
		t.Error("monolog should not be dev")
	}
	if d, ok := depMap["phpunit/phpunit"]; !ok {
		t.Error("missing phpunit/phpunit")
	} else if !d.IsDev {
		t.Error("phpunit should be dev")
	}
}

func TestComposerParser_ComposerLock_PackagesAndPackagesDev(t *testing.T) {
	dir := t.TempDir()
	content := `{
		"packages": [
			{"name": "monolog/monolog", "version": "3.5.0", "license": ["MIT"]},
			{"name": "symfony/console", "version": "7.0.1", "license": ["MIT"]}
		],
		"packages-dev": [
			{"name": "phpunit/phpunit", "version": "10.5.0", "license": ["BSD-3-Clause"]}
		]
	}`
	writeTempFile(t, dir, "composer.lock", content)

	p := &ComposerParser{}
	deps, err := p.Parse(filepath.Join(dir, "composer.lock"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(deps))
	}

	devCount := 0
	for _, d := range deps {
		if d.IsDev {
			devCount++
		}
	}
	if devCount != 1 {
		t.Errorf("expected 1 dev dep, got %d", devCount)
	}
}

func TestComposerParser_PhpExtensionFiltering(t *testing.T) {
	dir := t.TempDir()
	content := `{
		"require": {
			"ext-mbstring": "*",
			"ext-pdo": "*",
			"vendor/package": "^1.0"
		}
	}`
	writeTempFile(t, dir, "composer.json", content)

	p := &ComposerParser{}
	deps, err := p.Parse(filepath.Join(dir, "composer.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep (ext- filtered), got %d", len(deps))
	}
	if deps[0].Name != "vendor/package" {
		t.Errorf("expected vendor/package, got %s", deps[0].Name)
	}
}

func TestComposerParser_ExtractLicenses_FromLockFile(t *testing.T) {
	dir := t.TempDir()
	content := `{
		"packages": [
			{"name": "vendor/a", "version": "1.0.0", "license": ["MIT"]},
			{"name": "vendor/b", "version": "2.0.0", "license": ["Apache-2.0", "MIT"]}
		],
		"packages-dev": [
			{"name": "vendor/c", "version": "3.0.0", "license": ["GPL-3.0"]}
		]
	}`
	writeTempFile(t, dir, "composer.lock", content)

	p := &ComposerParser{}
	licenses := p.ExtractLicenses(filepath.Join(dir, "composer.lock"))
	if len(licenses) != 3 {
		t.Fatalf("expected 3 license entries, got %d", len(licenses))
	}

	licMap := map[string]models.LicenseInfo{}
	for _, l := range licenses {
		licMap[l.Dependency] = l
	}

	// Multiple licenses should be joined with ", "
	if licMap["vendor/b"].License != "Apache-2.0, MIT" {
		t.Errorf("expected 'Apache-2.0, MIT', got '%s'", licMap["vendor/b"].License)
	}

	for _, l := range licenses {
		if l.Ecosystem != models.EcosystemComposer {
			t.Errorf("expected composer ecosystem, got %s", l.Ecosystem)
		}
	}
}

func TestComposerParser_ExtractLicenses_SkipsNonLockFile(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "composer.json", `{"require": {"vendor/a": "^1.0"}}`)

	p := &ComposerParser{}
	licenses := p.ExtractLicenses(filepath.Join(dir, "composer.json"))
	if licenses != nil {
		t.Errorf("expected nil for non-lock file, got %v", licenses)
	}
}

func TestComposerParser_ExtractLicenses_MissingFile(t *testing.T) {
	p := &ComposerParser{}
	licenses := p.ExtractLicenses("/nonexistent/composer.lock")
	if licenses != nil {
		t.Errorf("expected nil for missing file, got %v", licenses)
	}
}

func TestComposerParser_ExtractLicenses_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "composer.lock", `{broken`)

	p := &ComposerParser{}
	licenses := p.ExtractLicenses(filepath.Join(dir, "composer.lock"))
	if licenses != nil {
		t.Errorf("expected nil for malformed JSON, got %v", licenses)
	}
}

func TestComposerParser_EmptyComposerJSON(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "composer.json", `{}`)

	p := &ComposerParser{}
	deps, err := p.Parse(filepath.Join(dir, "composer.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestComposerParser_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "composer.json", `not json`)

	p := &ComposerParser{}
	_, err := p.Parse(filepath.Join(dir, "composer.json"))
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestComposerParser_UnknownFile(t *testing.T) {
	p := &ComposerParser{}
	deps, err := p.Parse("/some/random.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deps != nil {
		t.Errorf("expected nil, got %v", deps)
	}
}
