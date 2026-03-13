package scanner

import (
	"path/filepath"
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestPubParser_Ecosystem(t *testing.T) {
	p := &PubParser{}
	if p.Ecosystem() != models.EcosystemPub {
		t.Errorf("expected pub, got %s", p.Ecosystem())
	}
}

func TestPubParser_Pubspec(t *testing.T) {
	dir := t.TempDir()
	content := `name: my_app
version: 1.0.0

dependencies:
  flutter:
    sdk: flutter
  http: ^1.1.0
  provider: ^6.0.0

dev_dependencies:
  flutter_test:
    sdk: flutter
  mockito: ^5.4.0
`
	writeTempFile(t, dir, "pubspec.yaml", content)

	p := &PubParser{}
	deps, err := p.Parse(filepath.Join(dir, "pubspec.yaml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	depMap := map[string]models.Dependency{}
	for _, d := range deps {
		depMap[d.Name] = d
	}

	if depMap["http"].Version != "^1.1.0" {
		t.Errorf("expected ^1.1.0, got %s", depMap["http"].Version)
	}
	if depMap["http"].IsDev {
		t.Error("http should not be dev")
	}
	if depMap["provider"].Version != "^6.0.0" {
		t.Errorf("expected ^6.0.0, got %s", depMap["provider"].Version)
	}

	if !depMap["mockito"].IsDev {
		t.Error("mockito should be dev")
	}

	// flutter SDK dep should have * version (complex nested dep)
	if depMap["flutter"].Version != "*" {
		t.Errorf("expected * for SDK dep, got %s", depMap["flutter"].Version)
	}
}

func TestPubParser_PubspecLock(t *testing.T) {
	dir := t.TempDir()
	content := `sdks:
  dart: ">=3.2.0 <4.0.0"
packages:
  http:
    dependency: "direct main"
    version: "1.1.2"
    source: hosted
  provider:
    dependency: "direct main"
    version: "6.1.1"
    source: hosted
  mockito:
    dependency: "direct dev"
    version: "5.4.3"
    source: hosted
  collection:
    dependency: transitive
    version: "1.18.0"
    source: hosted
`
	writeTempFile(t, dir, "pubspec.lock", content)

	p := &PubParser{}
	deps, err := p.Parse(filepath.Join(dir, "pubspec.lock"))
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

	if depMap["http"].Version != "1.1.2" {
		t.Errorf("expected 1.1.2, got %s", depMap["http"].Version)
	}
	if depMap["http"].IsDev {
		t.Error("http should not be dev")
	}

	if !depMap["mockito"].IsDev {
		t.Error("mockito should be dev")
	}

	if !depMap["collection"].IsDev {
		t.Error("transitive should be marked as dev")
	}
}

func TestPubParser_EmptyPubspec(t *testing.T) {
	dir := t.TempDir()
	content := `name: my_app
version: 1.0.0
`
	writeTempFile(t, dir, "pubspec.yaml", content)

	p := &PubParser{}
	deps, err := p.Parse(filepath.Join(dir, "pubspec.yaml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestPubParser_UnknownFile(t *testing.T) {
	p := &PubParser{}
	deps, err := p.Parse("/some/random.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deps != nil {
		t.Errorf("expected nil, got %v", deps)
	}
}

func TestPubParser_MissingFile(t *testing.T) {
	p := &PubParser{}
	_, err := p.Parse("/nonexistent/pubspec.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestPubParser_MissingLockFile(t *testing.T) {
	p := &PubParser{}
	_, err := p.Parse("/nonexistent/pubspec.lock")
	if err == nil {
		t.Error("expected error for missing lock file")
	}
}

func TestPubParser_SourcePathIsSet(t *testing.T) {
	dir := t.TempDir()
	content := `name: my_app
dependencies:
  http: ^1.0.0
`
	writeTempFile(t, dir, "pubspec.yaml", content)
	path := filepath.Join(dir, "pubspec.yaml")

	p := &PubParser{}
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

func TestPubParser_AllDepsHavePubEcosystem(t *testing.T) {
	dir := t.TempDir()
	content := `name: my_app
dependencies:
  http: ^1.0.0
  provider: ^6.0.0
dev_dependencies:
  mockito: ^5.0.0
`
	writeTempFile(t, dir, "pubspec.yaml", content)

	p := &PubParser{}
	deps, err := p.Parse(filepath.Join(dir, "pubspec.yaml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, d := range deps {
		if d.Ecosystem != models.EcosystemPub {
			t.Errorf("expected pub ecosystem, got %s", d.Ecosystem)
		}
	}
}

func TestPubParser_Pubspec_CommentsIgnored(t *testing.T) {
	dir := t.TempDir()
	content := `name: my_app
# This is a top-level comment
dependencies:
  # A dependency comment
  http: ^1.0.0
  # Another comment
  provider: ^6.0.0
`
	writeTempFile(t, dir, "pubspec.yaml", content)

	p := &PubParser{}
	deps, err := p.Parse(filepath.Join(dir, "pubspec.yaml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
}

func TestPubParser_Pubspec_SectionBoundary(t *testing.T) {
	dir := t.TempDir()
	content := `name: my_app
version: 1.0.0

dependencies:
  http: ^1.0.0

environment:
  sdk: ">=3.0.0 <4.0.0"

dev_dependencies:
  mockito: ^5.0.0
`
	writeTempFile(t, dir, "pubspec.yaml", content)

	p := &PubParser{}
	deps, err := p.Parse(filepath.Join(dir, "pubspec.yaml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	depMap := map[string]models.Dependency{}
	for _, d := range deps {
		depMap[d.Name] = d
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 deps (http + mockito), got %d", len(deps))
	}
	if depMap["http"].IsDev {
		t.Error("http should not be dev")
	}
	if !depMap["mockito"].IsDev {
		t.Error("mockito should be dev")
	}
}

func TestPubParser_PubspecLock_SourcePathIsSet(t *testing.T) {
	dir := t.TempDir()
	content := `packages:
  http:
    dependency: "direct main"
    version: "1.1.2"
    source: hosted
`
	writeTempFile(t, dir, "pubspec.lock", content)
	path := filepath.Join(dir, "pubspec.lock")

	p := &PubParser{}
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

func TestPubParser_PubspecLock_EmptyPackages(t *testing.T) {
	dir := t.TempDir()
	content := `sdks:
  dart: ">=3.2.0 <4.0.0"
packages:
`
	writeTempFile(t, dir, "pubspec.lock", content)

	p := &PubParser{}
	deps, err := p.Parse(filepath.Join(dir, "pubspec.lock"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestPubParser_PubspecLock_DirectMainNotDev(t *testing.T) {
	dir := t.TempDir()
	content := `packages:
  http:
    dependency: "direct main"
    version: "1.1.2"
    source: hosted
  path:
    dependency: "direct overridden"
    version: "1.9.0"
    source: hosted
`
	writeTempFile(t, dir, "pubspec.lock", content)

	p := &PubParser{}
	deps, err := p.Parse(filepath.Join(dir, "pubspec.lock"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, d := range deps {
		if d.Name == "http" && d.IsDev {
			t.Error("direct main should not be dev")
		}
		if d.Name == "path" && d.IsDev {
			t.Error("direct overridden should not be dev")
		}
	}
}

func TestPubParser_Pubspec_OnlyDeps(t *testing.T) {
	dir := t.TempDir()
	content := `name: my_app
dependencies:
  http: ^1.0.0
`
	writeTempFile(t, dir, "pubspec.yaml", content)

	p := &PubParser{}
	deps, err := p.Parse(filepath.Join(dir, "pubspec.yaml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].IsDev {
		t.Error("should not be dev")
	}
}

func TestPubParser_Pubspec_OnlyDevDeps(t *testing.T) {
	dir := t.TempDir()
	content := `name: my_app
dev_dependencies:
  mockito: ^5.0.0
`
	writeTempFile(t, dir, "pubspec.yaml", content)

	p := &PubParser{}
	deps, err := p.Parse(filepath.Join(dir, "pubspec.yaml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if !deps[0].IsDev {
		t.Error("should be dev")
	}
}
