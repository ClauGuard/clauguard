package scanner

import (
	"path/filepath"
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestPipParser_Ecosystem(t *testing.T) {
	p := &PipParser{}
	if p.Ecosystem() != models.EcosystemPip {
		t.Errorf("expected pip, got %s", p.Ecosystem())
	}
}

func TestPipParser_RequirementsTxt_VersionSpecifiers(t *testing.T) {
	dir := t.TempDir()
	content := `Django==4.2.0
requests>=2.28.0
flask~=3.0
numpy<=1.25.0
pandas!=2.0.0
simplejson
`
	writeTempFile(t, dir, "requirements.txt", content)

	p := &PipParser{}
	deps, err := p.Parse(filepath.Join(dir, "requirements.txt"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 6 {
		t.Fatalf("expected 6 deps, got %d", len(deps))
	}

	depMap := map[string]models.Dependency{}
	for _, d := range deps {
		depMap[d.Name] = d
	}

	if depMap["Django"].Version != "==4.2.0" {
		t.Errorf("expected ==4.2.0, got %s", depMap["Django"].Version)
	}
	if depMap["requests"].Version != ">=2.28.0" {
		t.Errorf("expected >=2.28.0, got %s", depMap["requests"].Version)
	}
	if depMap["flask"].Version != "~=3.0" {
		t.Errorf("expected ~=3.0, got %s", depMap["flask"].Version)
	}
	if depMap["simplejson"].Version != "*" {
		t.Errorf("expected * for unversioned dep, got %s", depMap["simplejson"].Version)
	}
}

func TestPipParser_RequirementsTxt_CommentsAndOptions(t *testing.T) {
	dir := t.TempDir()
	content := `# This is a comment
-r base.txt
--index-url https://pypi.org/simple/
-e git+https://github.com/foo/bar.git
Django==4.2.0

# Another comment
requests>=2.28.0
`
	writeTempFile(t, dir, "requirements.txt", content)

	p := &PipParser{}
	deps, err := p.Parse(filepath.Join(dir, "requirements.txt"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Comments (#), empty lines, and option lines (-) should be skipped
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
}

func TestPipParser_RequirementsTxt_Extras(t *testing.T) {
	dir := t.TempDir()
	content := `celery[redis,sqs]==5.3.0
requests[security]>=2.28.0
`
	writeTempFile(t, dir, "requirements.txt", content)

	p := &PipParser{}
	deps, err := p.Parse(filepath.Join(dir, "requirements.txt"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}

	depMap := map[string]models.Dependency{}
	for _, d := range deps {
		depMap[d.Name] = d
	}

	if _, ok := depMap["celery"]; !ok {
		t.Error("expected extras to be stripped, missing celery")
	}
	if depMap["celery"].Version != "==5.3.0" {
		t.Errorf("expected ==5.3.0, got %s", depMap["celery"].Version)
	}
}

func TestPipParser_RequirementsTxt_EnvironmentMarkers(t *testing.T) {
	dir := t.TempDir()
	content := `pywin32==306; sys_platform == "win32"
colorama>=0.4.0; os_name == "nt"
`
	writeTempFile(t, dir, "requirements.txt", content)

	p := &PipParser{}
	deps, err := p.Parse(filepath.Join(dir, "requirements.txt"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}

	depMap := map[string]models.Dependency{}
	for _, d := range deps {
		depMap[d.Name] = d
	}

	if depMap["pywin32"].Version != "==306" {
		t.Errorf("expected ==306, got %s", depMap["pywin32"].Version)
	}
}

func TestPipParser_PyprojectToml_Dependencies(t *testing.T) {
	dir := t.TempDir()
	content := `[project]
name = "myproject"
version = "1.0.0"
dependencies = [
    "Django>=4.2",
    "requests~=2.28.0",
    "simplejson",
]
`
	writeTempFile(t, dir, "pyproject.toml", content)

	p := &PipParser{}
	deps, err := p.Parse(filepath.Join(dir, "pyproject.toml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(deps))
	}

	depMap := map[string]models.Dependency{}
	for _, d := range deps {
		depMap[d.Name] = d
	}

	if depMap["Django"].Version != ">=4.2" {
		t.Errorf("expected >=4.2, got %s", depMap["Django"].Version)
	}
	if depMap["simplejson"].Version != "*" {
		t.Errorf("expected *, got %s", depMap["simplejson"].Version)
	}
}

func TestPipParser_PyprojectToml_NoDependencies(t *testing.T) {
	dir := t.TempDir()
	content := `[project]
name = "myproject"
version = "1.0.0"
`
	writeTempFile(t, dir, "pyproject.toml", content)

	p := &PipParser{}
	deps, err := p.Parse(filepath.Join(dir, "pyproject.toml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestPipParser_EmptyRequirementsTxt(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "requirements.txt", "")

	p := &PipParser{}
	deps, err := p.Parse(filepath.Join(dir, "requirements.txt"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestPipParser_UnknownFile(t *testing.T) {
	p := &PipParser{}
	deps, err := p.Parse("/some/setup.cfg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deps != nil {
		t.Errorf("expected nil, got %v", deps)
	}
}

func TestPipParser_MissingFile(t *testing.T) {
	p := &PipParser{}
	_, err := p.Parse("/nonexistent/requirements.txt")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseRequirement_EdgeCases(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
	}{
		{"Django==4.2.0", "Django", "==4.2.0"},
		{"requests>=2.28", "requests", ">=2.28"},
		{"flask~=3.0", "flask", "~=3.0"},
		{"numpy<=1.25", "numpy", "<=1.25"},
		{"pandas!=2.0", "pandas", "!=2.0"},
		{"simplejson", "simplejson", "*"},
		{"", "", ""},
		{"pkg[extra]==1.0", "pkg", "==1.0"},
		{"pkg[a,b]>=2.0", "pkg", ">=2.0"},
		{"  spaced  ", "spaced", "*"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, version := parseRequirement(tt.input)
			if name != tt.wantName {
				t.Errorf("parseRequirement(%q) name = %q, want %q", tt.input, name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("parseRequirement(%q) version = %q, want %q", tt.input, version, tt.wantVersion)
			}
		})
	}
}
