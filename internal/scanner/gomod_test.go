package scanner

import (
	"path/filepath"
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestGoModParser_Ecosystem(t *testing.T) {
	p := &GoModParser{}
	if p.Ecosystem() != models.EcosystemGo {
		t.Errorf("expected go, got %s", p.Ecosystem())
	}
}

func TestGoModParser_MultiLineRequireBlock(t *testing.T) {
	dir := t.TempDir()
	content := `module example.com/mymod

go 1.21

require (
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.4
	golang.org/x/net v0.17.0 // indirect
)
`
	writeTempFile(t, dir, "go.mod", content)

	p := &GoModParser{}
	deps, err := p.Parse(filepath.Join(dir, "go.mod"))
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

	if d, ok := depMap["github.com/pkg/errors"]; !ok {
		t.Error("missing github.com/pkg/errors")
	} else if d.Version != "v0.9.1" {
		t.Errorf("expected v0.9.1, got %s", d.Version)
	}

	// Indirect dep should still be parsed (comment stripped)
	if d, ok := depMap["golang.org/x/net"]; !ok {
		t.Error("missing golang.org/x/net (indirect)")
	} else if d.Version != "v0.17.0" {
		t.Errorf("expected v0.17.0, got %s", d.Version)
	}

	for _, d := range deps {
		if d.Ecosystem != models.EcosystemGo {
			t.Errorf("expected go ecosystem, got %s", d.Ecosystem)
		}
	}
}

func TestGoModParser_SingleLineRequire(t *testing.T) {
	dir := t.TempDir()
	content := `module example.com/mymod

go 1.21

require github.com/spf13/cobra v1.7.0
`
	writeTempFile(t, dir, "go.mod", content)

	p := &GoModParser{}
	deps, err := p.Parse(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Name != "github.com/spf13/cobra" {
		t.Errorf("expected github.com/spf13/cobra, got %s", deps[0].Name)
	}
	if deps[0].Version != "v1.7.0" {
		t.Errorf("expected v1.7.0, got %s", deps[0].Version)
	}
}

func TestGoModParser_MixedSingleAndMultiLine(t *testing.T) {
	dir := t.TempDir()
	content := `module example.com/mymod

go 1.21

require github.com/single/dep v1.0.0

require (
	github.com/multi/dep1 v2.0.0
	github.com/multi/dep2 v3.0.0
)
`
	writeTempFile(t, dir, "go.mod", content)

	p := &GoModParser{}
	deps, err := p.Parse(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(deps))
	}
}

func TestGoModParser_CommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	content := `module example.com/mymod

go 1.21

require (
	// This is a comment
	github.com/pkg/errors v0.9.1

	github.com/other/pkg v1.0.0
)
`
	writeTempFile(t, dir, "go.mod", content)

	p := &GoModParser{}
	deps, err := p.Parse(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Comment-only line should result in no parts after stripping => skipped
	// Blank line inside require block: no parts => skipped
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
}

func TestGoModParser_SkipsGoSum(t *testing.T) {
	dir := t.TempDir()
	content := `github.com/pkg/errors v0.9.1 h1:abc123=
github.com/pkg/errors v0.9.1/go.mod h1:def456=
`
	writeTempFile(t, dir, "go.sum", content)

	p := &GoModParser{}
	deps, err := p.Parse(filepath.Join(dir, "go.sum"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deps != nil {
		t.Errorf("expected nil for go.sum, got %v", deps)
	}
}

func TestGoModParser_EmptyGoMod(t *testing.T) {
	dir := t.TempDir()
	content := `module example.com/mymod

go 1.21
`
	writeTempFile(t, dir, "go.mod", content)

	p := &GoModParser{}
	deps, err := p.Parse(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestGoModParser_MissingFile(t *testing.T) {
	p := &GoModParser{}
	_, err := p.Parse("/nonexistent/go.mod")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestGoModParser_IndirectDepsNotMarkedDev(t *testing.T) {
	dir := t.TempDir()
	content := `module example.com/mymod

go 1.21

require (
	github.com/direct/dep v1.0.0
	github.com/indirect/dep v2.0.0 // indirect
)
`
	writeTempFile(t, dir, "go.mod", content)

	p := &GoModParser{}
	deps, err := p.Parse(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, d := range deps {
		if d.IsDev {
			t.Errorf("Go deps should not be marked as dev, but %s was", d.Name)
		}
	}
}
