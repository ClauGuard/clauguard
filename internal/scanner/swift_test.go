package scanner

import (
	"path/filepath"
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestSwiftParser_Ecosystem(t *testing.T) {
	p := &SwiftParser{}
	if p.Ecosystem() != models.EcosystemSwift {
		t.Errorf("expected swift, got %s", p.Ecosystem())
	}
}

func TestSwiftParser_BasicPackageSwift(t *testing.T) {
	dir := t.TempDir()
	content := `// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.2.0"),
        .package(url: "https://github.com/vapor/vapor.git", from: "4.89.0"),
    ],
    targets: [
        .target(name: "MyApp", dependencies: ["ArgumentParser", "Vapor"]),
    ]
)
`
	writeTempFile(t, dir, "Package.swift", content)

	p := &SwiftParser{}
	deps, err := p.Parse(filepath.Join(dir, "Package.swift"))
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

	if depMap["apple/swift-argument-parser"].Version != "1.2.0" {
		t.Errorf("expected 1.2.0, got %s", depMap["apple/swift-argument-parser"].Version)
	}
	if depMap["vapor/vapor"].Version != "4.89.0" {
		t.Errorf("expected 4.89.0, got %s", depMap["vapor/vapor"].Version)
	}
}

func TestSwiftParser_ExactVersion(t *testing.T) {
	dir := t.TempDir()
	content := `import PackageDescription
let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/pointfreeco/swift-composable-architecture", exact: "1.5.0"),
    ]
)
`
	writeTempFile(t, dir, "Package.swift", content)

	p := &SwiftParser{}
	deps, err := p.Parse(filepath.Join(dir, "Package.swift"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Version != "1.5.0" {
		t.Errorf("expected 1.5.0, got %s", deps[0].Version)
	}
}

func TestSwiftParser_UpToNextMajor(t *testing.T) {
	dir := t.TempDir()
	content := `import PackageDescription
let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/Alamofire/Alamofire.git", .upToNextMajor(from: "5.8.0")),
    ]
)
`
	writeTempFile(t, dir, "Package.swift", content)

	p := &SwiftParser{}
	deps, err := p.Parse(filepath.Join(dir, "Package.swift"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Version != "5.8.0" {
		t.Errorf("expected 5.8.0, got %s", deps[0].Version)
	}
	if deps[0].Name != "Alamofire/Alamofire" {
		t.Errorf("expected Alamofire/Alamofire, got %s", deps[0].Name)
	}
}

func TestSwiftParser_EmptyPackage(t *testing.T) {
	dir := t.TempDir()
	content := `import PackageDescription
let package = Package(
    name: "MyApp",
    dependencies: [],
    targets: []
)
`
	writeTempFile(t, dir, "Package.swift", content)

	p := &SwiftParser{}
	deps, err := p.Parse(filepath.Join(dir, "Package.swift"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestSwiftParser_UnknownFile(t *testing.T) {
	p := &SwiftParser{}
	deps, err := p.Parse("/some/random.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deps != nil {
		t.Errorf("expected nil, got %v", deps)
	}
}

func TestSwiftParser_MissingFile(t *testing.T) {
	p := &SwiftParser{}
	_, err := p.Parse("/nonexistent/Package.swift")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestExtractSwiftPackageName_GitHub(t *testing.T) {
	got := extractSwiftPackageName("https://github.com/apple/swift-nio.git")
	if got != "apple/swift-nio" {
		t.Errorf("expected apple/swift-nio, got %s", got)
	}
}

func TestExtractSwiftPackageName_GitLab(t *testing.T) {
	got := extractSwiftPackageName("https://gitlab.com/org/repo")
	if got != "org/repo" {
		t.Errorf("expected org/repo, got %s", got)
	}
}

func TestExtractSwiftPackageName_CustomHost(t *testing.T) {
	got := extractSwiftPackageName("https://custom.host/org/repo.git")
	if got != "org/repo" {
		t.Errorf("expected org/repo, got %s", got)
	}
}

func TestSwiftParser_SourcePathIsSet(t *testing.T) {
	dir := t.TempDir()
	content := `import PackageDescription
let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/org/repo", from: "1.0.0"),
    ]
)
`
	writeTempFile(t, dir, "Package.swift", content)
	path := filepath.Join(dir, "Package.swift")

	p := &SwiftParser{}
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

func TestSwiftParser_AllDepsHaveSwiftEcosystem(t *testing.T) {
	dir := t.TempDir()
	content := `import PackageDescription
let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio", from: "2.0.0"),
        .package(url: "https://github.com/vapor/vapor.git", from: "4.0.0"),
    ]
)
`
	writeTempFile(t, dir, "Package.swift", content)

	p := &SwiftParser{}
	deps, err := p.Parse(filepath.Join(dir, "Package.swift"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, d := range deps {
		if d.Ecosystem != models.EcosystemSwift {
			t.Errorf("expected swift ecosystem, got %s", d.Ecosystem)
		}
	}
}

func TestSwiftParser_NoVersionFallsBackToWildcard(t *testing.T) {
	dir := t.TempDir()
	// Branch-based dependency with no from/exact
	content := `import PackageDescription
let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/org/repo", branch: "main"),
    ]
)
`
	writeTempFile(t, dir, "Package.swift", content)

	p := &SwiftParser{}
	deps, err := p.Parse(filepath.Join(dir, "Package.swift"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Version != "*" {
		t.Errorf("expected * for branch dep, got %s", deps[0].Version)
	}
}

func TestSwiftParser_UpToNextMinor(t *testing.T) {
	dir := t.TempDir()
	content := `import PackageDescription
let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/org/repo.git", .upToNextMinor(from: "3.2.1")),
    ]
)
`
	writeTempFile(t, dir, "Package.swift", content)

	p := &SwiftParser{}
	deps, err := p.Parse(filepath.Join(dir, "Package.swift"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Version != "3.2.1" {
		t.Errorf("expected 3.2.1, got %s", deps[0].Version)
	}
}

func TestSwiftParser_MultipleDepsOnSameLine(t *testing.T) {
	dir := t.TempDir()
	// Each .package should be on its own line in real code, but test robustness
	content := `import PackageDescription
let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/org/a", from: "1.0.0"),
        .package(url: "https://github.com/org/b", from: "2.0.0"),
        .package(url: "https://github.com/org/c", exact: "3.0.0"),
    ]
)
`
	writeTempFile(t, dir, "Package.swift", content)

	p := &SwiftParser{}
	deps, err := p.Parse(filepath.Join(dir, "Package.swift"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(deps))
	}
}

func TestExtractSwiftPackageName_BitBucket(t *testing.T) {
	got := extractSwiftPackageName("https://bitbucket.org/team/repo.git")
	if got != "team/repo" {
		t.Errorf("expected team/repo, got %s", got)
	}
}

func TestExtractSwiftPackageName_NoGitSuffix(t *testing.T) {
	got := extractSwiftPackageName("https://github.com/apple/swift-nio")
	if got != "apple/swift-nio" {
		t.Errorf("expected apple/swift-nio, got %s", got)
	}
}
