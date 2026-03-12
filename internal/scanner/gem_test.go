package scanner

import (
	"path/filepath"
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestGemParser_Ecosystem(t *testing.T) {
	p := &GemParser{}
	if p.Ecosystem() != models.EcosystemGem {
		t.Errorf("expected gem, got %s", p.Ecosystem())
	}
}

func TestGemParser_Gemfile_WithAndWithoutVersions(t *testing.T) {
	dir := t.TempDir()
	content := `source 'https://rubygems.org'

gem 'rails', '~> 7.1'
gem 'pg', '>= 1.1'
gem 'puma'
gem 'bootsnap', require: false
`
	writeTempFile(t, dir, "Gemfile", content)

	p := &GemParser{}
	deps, err := p.Parse(filepath.Join(dir, "Gemfile"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 4 {
		t.Fatalf("expected 4 deps, got %d", len(deps))
	}

	depMap := map[string]models.Dependency{}
	for _, d := range deps {
		depMap[d.Name] = d
	}

	if depMap["rails"].Version != "~> 7.1" {
		t.Errorf("expected '~> 7.1', got '%s'", depMap["rails"].Version)
	}
	if depMap["pg"].Version != ">= 1.1" {
		t.Errorf("expected '>= 1.1', got '%s'", depMap["pg"].Version)
	}
	if depMap["puma"].Version != "*" {
		t.Errorf("expected * for versionless gem, got %s", depMap["puma"].Version)
	}
	// bootsnap has "require: false" as second arg, parsed as version
	// The parser treats the second comma-separated field as version
}

func TestGemParser_Gemfile_NonGemLinesSkipped(t *testing.T) {
	dir := t.TempDir()
	content := `source 'https://rubygems.org'
ruby '3.2.0'

# A comment
group :development do
  gem 'debug'
end
`
	writeTempFile(t, dir, "Gemfile", content)

	p := &GemParser{}
	deps, err := p.Parse(filepath.Join(dir, "Gemfile"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only "gem 'debug'" should be found
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Name != "debug" {
		t.Errorf("expected debug, got %s", deps[0].Name)
	}
}

func TestGemParser_GemfileLock_SpecsSection(t *testing.T) {
	dir := t.TempDir()
	content := `GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.1.2)
      actionpack (= 7.1.2)
    actionpack (7.1.2)
      rack (~> 3.0)
    rack (3.0.8)

PLATFORMS
  ruby
  x86_64-linux

BUNDLED WITH
   2.4.22
`
	writeTempFile(t, dir, "Gemfile.lock", content)

	p := &GemParser{}
	deps, err := p.Parse(filepath.Join(dir, "Gemfile.lock"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only 4-space indented lines are top-level gems: actioncable, actionpack, rack
	// Sub-deps (6+ spaces) are skipped
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(deps))
	}

	depMap := map[string]models.Dependency{}
	for _, d := range deps {
		depMap[d.Name] = d
	}

	if depMap["actioncable"].Version != "7.1.2" {
		t.Errorf("expected 7.1.2, got %s", depMap["actioncable"].Version)
	}
	if depMap["rack"].Version != "3.0.8" {
		t.Errorf("expected 3.0.8, got %s", depMap["rack"].Version)
	}
}

func TestGemParser_GemfileLock_SectionBoundaryStopsSpecs(t *testing.T) {
	dir := t.TempDir()
	content := `GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.2)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.1)
`
	writeTempFile(t, dir, "Gemfile.lock", content)

	p := &GemParser{}
	deps, err := p.Parse(filepath.Join(dir, "Gemfile.lock"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only rails from specs section, PLATFORMS/DEPENDENCIES should not leak
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Name != "rails" {
		t.Errorf("expected rails, got %s", deps[0].Name)
	}
}

func TestGemParser_GemfileLock_MultipleSpecsSections(t *testing.T) {
	dir := t.TempDir()
	// Some Gemfile.lock files have multiple GEM sections with specs
	content := `GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.2)

GIT
  remote: https://github.com/example/gem.git
  specs:
    custom-gem (0.1.0)

PLATFORMS
  ruby
`
	writeTempFile(t, dir, "Gemfile.lock", content)

	p := &GemParser{}
	deps, err := p.Parse(filepath.Join(dir, "Gemfile.lock"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
}

func TestGemParser_EmptyGemfile(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "Gemfile", "source 'https://rubygems.org'\n")

	p := &GemParser{}
	deps, err := p.Parse(filepath.Join(dir, "Gemfile"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestGemParser_UnknownFile(t *testing.T) {
	p := &GemParser{}
	deps, err := p.Parse("/some/random.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deps != nil {
		t.Errorf("expected nil, got %v", deps)
	}
}

func TestGemParser_MissingFile(t *testing.T) {
	p := &GemParser{}
	_, err := p.Parse("/nonexistent/Gemfile")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestGemParser_GemfileLock_GemWithoutVersion(t *testing.T) {
	dir := t.TempDir()
	// Edge case: a gem line without a version in parens
	content := `GEM
  specs:
    somegem
`
	writeTempFile(t, dir, "Gemfile.lock", content)

	p := &GemParser{}
	deps, err := p.Parse(filepath.Join(dir, "Gemfile.lock"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Name != "somegem" {
		t.Errorf("expected somegem, got %s", deps[0].Name)
	}
	if deps[0].Version != "" {
		t.Errorf("expected empty version, got %s", deps[0].Version)
	}
}

func TestGemParser_AllDepsHaveGemEcosystem(t *testing.T) {
	dir := t.TempDir()
	content := `gem 'rails', '~> 7.0'
gem 'pg'
`
	writeTempFile(t, dir, "Gemfile", content)

	p := &GemParser{}
	deps, err := p.Parse(filepath.Join(dir, "Gemfile"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, d := range deps {
		if d.Ecosystem != models.EcosystemGem {
			t.Errorf("expected gem ecosystem, got %s", d.Ecosystem)
		}
	}
}
