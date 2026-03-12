package scanner

import (
	"path/filepath"
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestNpmParser_Ecosystem(t *testing.T) {
	p := &NpmParser{}
	if p.Ecosystem() != models.EcosystemNpm {
		t.Errorf("expected npm, got %s", p.Ecosystem())
	}
}

func TestNpmParser_PackageJSON_DepsAndDevDeps(t *testing.T) {
	dir := t.TempDir()
	content := `{
		"dependencies": {
			"express": "^4.18.0",
			"lodash": "~4.17.21"
		},
		"devDependencies": {
			"jest": "^29.0.0"
		}
	}`
	writeTempFile(t, dir, "package.json", content)

	p := &NpmParser{}
	deps, err := p.Parse(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(deps))
	}

	devCount := 0
	prodCount := 0
	for _, d := range deps {
		if d.Ecosystem != models.EcosystemNpm {
			t.Errorf("expected npm ecosystem, got %s", d.Ecosystem)
		}
		if d.IsDev {
			devCount++
		} else {
			prodCount++
		}
	}
	if prodCount != 2 {
		t.Errorf("expected 2 prod deps, got %d", prodCount)
	}
	if devCount != 1 {
		t.Errorf("expected 1 dev dep, got %d", devCount)
	}
}

func TestNpmParser_PackageLockJSON_NestedAndScoped(t *testing.T) {
	dir := t.TempDir()
	content := `{
		"packages": {
			"": {"version": "1.0.0"},
			"node_modules/express": {"version": "4.18.2", "dev": false},
			"node_modules/@scope/utils": {"version": "2.0.0", "dev": false},
			"node_modules/express/node_modules/qs": {"version": "6.11.0", "dev": false},
			"node_modules/jest": {"version": "29.7.0", "dev": true}
		}
	}`
	writeTempFile(t, dir, "package-lock.json", content)

	p := &NpmParser{}
	deps, err := p.Parse(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Root package ("") should be skipped => 4 deps
	if len(deps) != 4 {
		t.Fatalf("expected 4 deps, got %d", len(deps))
	}

	depMap := map[string]models.Dependency{}
	for _, d := range deps {
		depMap[d.Name] = d
	}

	// Scoped package name extraction
	if d, ok := depMap["@scope/utils"]; !ok {
		t.Error("missing @scope/utils")
	} else if d.Version != "2.0.0" {
		t.Errorf("expected version 2.0.0, got %s", d.Version)
	}

	// Nested node_modules — should extract just "qs"
	if d, ok := depMap["qs"]; !ok {
		t.Error("missing nested dep qs")
	} else if d.Version != "6.11.0" {
		t.Errorf("expected version 6.11.0, got %s", d.Version)
	}

	// Dev flag
	if d, ok := depMap["jest"]; !ok {
		t.Error("missing jest")
	} else if !d.IsDev {
		t.Error("expected jest to be dev dep")
	}
}

func TestNpmParser_EmptyPackageJSON(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "package.json", `{}`)

	p := &NpmParser{}
	deps, err := p.Parse(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestNpmParser_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "package.json", `{not valid json}`)

	p := &NpmParser{}
	_, err := p.Parse(filepath.Join(dir, "package.json"))
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestNpmParser_MalformedLockJSON(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "package-lock.json", `{broken`)

	p := &NpmParser{}
	_, err := p.Parse(filepath.Join(dir, "package-lock.json"))
	if err == nil {
		t.Error("expected error for malformed lock JSON")
	}
}

func TestNpmParser_UnknownFile(t *testing.T) {
	p := &NpmParser{}
	deps, err := p.Parse("/some/unknown.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deps != nil {
		t.Errorf("expected nil for unknown file, got %v", deps)
	}
}

func TestNpmParser_MissingFile(t *testing.T) {
	p := &NpmParser{}
	_, err := p.Parse("/nonexistent/package.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestNpmParser_SourcePathIsSet(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "package.json", `{"dependencies": {"pkg": "1.0.0"}}`)
	path := filepath.Join(dir, "package.json")

	p := &NpmParser{}
	deps, err := p.Parse(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Source != path {
		t.Errorf("expected source %s, got %s", path, deps[0].Source)
	}
}
