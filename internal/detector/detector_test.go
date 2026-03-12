package detector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestDetect_FindsAllManifestTypes(t *testing.T) {
	tests := []struct {
		name      string
		filename  string
		ecosystem models.Ecosystem
	}{
		{"package.json", "package.json", models.EcosystemNpm},
		{"package-lock.json", "package-lock.json", models.EcosystemNpm},
		{"yarn.lock", "yarn.lock", models.EcosystemNpm},
		{"pnpm-lock.yaml", "pnpm-lock.yaml", models.EcosystemNpm},
		{"composer.json", "composer.json", models.EcosystemComposer},
		{"composer.lock", "composer.lock", models.EcosystemComposer},
		{"requirements.txt", "requirements.txt", models.EcosystemPip},
		{"Pipfile", "Pipfile", models.EcosystemPip},
		{"Pipfile.lock", "Pipfile.lock", models.EcosystemPip},
		{"pyproject.toml", "pyproject.toml", models.EcosystemPip},
		{"poetry.lock", "poetry.lock", models.EcosystemPip},
		{"go.mod", "go.mod", models.EcosystemGo},
		{"go.sum", "go.sum", models.EcosystemGo},
		{"Cargo.toml", "Cargo.toml", models.EcosystemCargo},
		{"Cargo.lock", "Cargo.lock", models.EcosystemCargo},
		{"Gemfile", "Gemfile", models.EcosystemGem},
		{"Gemfile.lock", "Gemfile.lock", models.EcosystemGem},
		{"pom.xml", "pom.xml", models.EcosystemMaven},
		{"build.gradle", "build.gradle", models.EcosystemGradle},
		{"build.gradle.kts", "build.gradle.kts", models.EcosystemGradle},
		{"packages.config", "packages.config", models.EcosystemNuget},
		{"Package.swift", "Package.swift", models.EcosystemSwift},
		{"Podfile", "Podfile", models.EcosystemCocoaPod},
		{"Podfile.lock", "Podfile.lock", models.EcosystemCocoaPod},
		{"pubspec.yaml", "pubspec.yaml", models.EcosystemPub},
		{"pubspec.lock", "pubspec.lock", models.EcosystemPub},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			createFile(t, dir, tt.filename)

			manifests, err := Detect(dir)
			if err != nil {
				t.Fatalf("Detect() returned error: %v", err)
			}

			if len(manifests) != 1 {
				t.Fatalf("expected 1 manifest, got %d", len(manifests))
			}

			if manifests[0].Ecosystem != tt.ecosystem {
				t.Errorf("expected ecosystem %q, got %q", tt.ecosystem, manifests[0].Ecosystem)
			}

			expectedPath := filepath.Join(dir, tt.filename)
			if manifests[0].Path != expectedPath {
				t.Errorf("expected path %q, got %q", expectedPath, manifests[0].Path)
			}
		})
	}
}

func TestDetect_FindsMultipleManifests(t *testing.T) {
	dir := t.TempDir()
	createFile(t, dir, "package.json")
	createFile(t, dir, "go.mod")

	sub := filepath.Join(dir, "subproject")
	mustMkdir(t, sub)
	createFile(t, sub, "Cargo.toml")

	manifests, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if len(manifests) != 3 {
		t.Fatalf("expected 3 manifests, got %d", len(manifests))
	}

	ecosystems := make(map[models.Ecosystem]bool)
	for _, m := range manifests {
		ecosystems[m.Ecosystem] = true
	}

	for _, eco := range []models.Ecosystem{models.EcosystemNpm, models.EcosystemGo, models.EcosystemCargo} {
		if !ecosystems[eco] {
			t.Errorf("expected ecosystem %q to be detected", eco)
		}
	}
}

func TestDetect_SkipsDirs(t *testing.T) {
	tests := []struct {
		name    string
		skipDir string
	}{
		{"node_modules", "node_modules"},
		{"vendor", "vendor"},
		{".git", ".git"},
		{".hg", ".hg"},
		{".svn", ".svn"},
		{"__pycache__", "__pycache__"},
		{".tox", ".tox"},
		{".venv", ".venv"},
		{"venv", "venv"},
		{"target", "target"},
		{"build", "build"},
		{"dist", "dist"},
		{"Pods", "Pods"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			skipped := filepath.Join(dir, tt.skipDir)
			mustMkdir(t, skipped)
			createFile(t, skipped, "package.json")

			// Place a manifest at root level so we know detection itself works.
			createFile(t, dir, "go.mod")

			manifests, err := Detect(dir)
			if err != nil {
				t.Fatalf("Detect() returned error: %v", err)
			}

			for _, m := range manifests {
				rel, _ := filepath.Rel(dir, m.Path)
				if filepath.Dir(rel) == tt.skipDir {
					t.Errorf("manifest inside %q should have been skipped, but found %q", tt.skipDir, m.Path)
				}
			}

			if len(manifests) != 1 {
				t.Errorf("expected 1 manifest (go.mod at root), got %d", len(manifests))
			}
		})
	}
}

func TestDetect_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()

	// Create a real file in a subdirectory.
	sub := filepath.Join(dir, "real")
	mustMkdir(t, sub)
	createFile(t, sub, "package.json")

	// Create a symlink to that file at the root level.
	symlink := filepath.Join(dir, "package.json")
	if err := os.Symlink(filepath.Join(sub, "package.json"), symlink); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	manifests, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// Only the real file should be detected, not the symlink.
	for _, m := range manifests {
		if m.Path == symlink {
			t.Errorf("symlink %q should have been skipped", symlink)
		}
	}

	if len(manifests) != 1 {
		t.Errorf("expected 1 manifest (real file only), got %d", len(manifests))
	}
}

func TestDetect_CsprojPatternMatching(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantHit  bool
	}{
		{"standard .csproj", "MyApp.csproj", true},
		{"dotted name .csproj", "My.App.Web.csproj", true},
		{"plain .csproj", ".csproj", true},
		{"non-csproj suffix", "MyApp.csproj.bak", false},
		{"partial match", "csproj", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			createFile(t, dir, tt.filename)

			manifests, err := Detect(dir)
			if err != nil {
				t.Fatalf("Detect() returned error: %v", err)
			}

			found := false
			for _, m := range manifests {
				if m.Ecosystem == models.EcosystemNuget {
					found = true
				}
			}

			if found != tt.wantHit {
				t.Errorf("expected nuget detected=%v for file %q, got %v", tt.wantHit, tt.filename, found)
			}
		})
	}
}

func TestDetect_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	manifests, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if len(manifests) != 0 {
		t.Errorf("expected 0 manifests in empty dir, got %d", len(manifests))
	}
}

func TestDetect_UnreadablePath(t *testing.T) {
	dir := t.TempDir()

	// Create a subdirectory with a manifest, then make it unreadable.
	sub := filepath.Join(dir, "secret")
	mustMkdir(t, sub)
	createFile(t, sub, "package.json")
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Skipf("cannot change permissions: %v", err)
	}
	t.Cleanup(func() { os.Chmod(sub, 0o755) })

	// Place a readable manifest at root.
	createFile(t, dir, "go.mod")

	manifests, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() should not return error for unreadable paths, got: %v", err)
	}

	// Should still find the readable manifest.
	if len(manifests) != 1 {
		t.Errorf("expected 1 manifest (go.mod), got %d", len(manifests))
	}
}

func TestDetect_NonExistentPath(t *testing.T) {
	// WalkDir skips unreadable paths via the error callback returning nil,
	// so a non-existent root returns empty results without an error.
	manifests, err := Detect("/nonexistent/path/that/does/not/exist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(manifests) != 0 {
		t.Errorf("expected 0 manifests for non-existent path, got %d", len(manifests))
	}
}

func TestDetect_NestedDirectories(t *testing.T) {
	dir := t.TempDir()

	// Create nested structure: root/a/b/c with manifests at different levels.
	createFile(t, dir, "package.json")

	a := filepath.Join(dir, "a")
	mustMkdir(t, a)
	createFile(t, a, "go.mod")

	b := filepath.Join(a, "b")
	mustMkdir(t, b)
	createFile(t, b, "Cargo.toml")

	c := filepath.Join(b, "c")
	mustMkdir(t, c)
	createFile(t, c, "composer.json")

	manifests, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if len(manifests) != 4 {
		t.Fatalf("expected 4 manifests across nested dirs, got %d", len(manifests))
	}
}

func TestDetect_IgnoresNonManifestFiles(t *testing.T) {
	dir := t.TempDir()
	createFile(t, dir, "README.md")
	createFile(t, dir, "main.go")
	createFile(t, dir, "Dockerfile")
	createFile(t, dir, "random.txt")

	manifests, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if len(manifests) != 0 {
		t.Errorf("expected 0 manifests for non-manifest files, got %d", len(manifests))
	}
}

func TestDetectedEcosystems_Deduplication(t *testing.T) {
	manifests := []DetectedManifest{
		{Path: "/a/package.json", Ecosystem: models.EcosystemNpm},
		{Path: "/a/package-lock.json", Ecosystem: models.EcosystemNpm},
		{Path: "/a/yarn.lock", Ecosystem: models.EcosystemNpm},
		{Path: "/a/go.mod", Ecosystem: models.EcosystemGo},
		{Path: "/a/go.sum", Ecosystem: models.EcosystemGo},
		{Path: "/a/Cargo.toml", Ecosystem: models.EcosystemCargo},
	}

	ecosystems := DetectedEcosystems(manifests)

	if len(ecosystems) != 3 {
		t.Fatalf("expected 3 unique ecosystems, got %d: %v", len(ecosystems), ecosystems)
	}

	seen := make(map[models.Ecosystem]bool)
	for _, e := range ecosystems {
		if seen[e] {
			t.Errorf("duplicate ecosystem %q in result", e)
		}
		seen[e] = true
	}

	for _, expected := range []models.Ecosystem{models.EcosystemNpm, models.EcosystemGo, models.EcosystemCargo} {
		if !seen[expected] {
			t.Errorf("expected ecosystem %q in result", expected)
		}
	}
}

func TestDetectedEcosystems_EmptyInput(t *testing.T) {
	tests := []struct {
		name      string
		manifests []DetectedManifest
	}{
		{"nil slice", nil},
		{"empty slice", []DetectedManifest{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ecosystems := DetectedEcosystems(tt.manifests)
			if len(ecosystems) != 0 {
				t.Errorf("expected 0 ecosystems, got %d: %v", len(ecosystems), ecosystems)
			}
		})
	}
}

func TestDetectedEcosystems_PreservesOrder(t *testing.T) {
	manifests := []DetectedManifest{
		{Path: "/a/Cargo.toml", Ecosystem: models.EcosystemCargo},
		{Path: "/a/package.json", Ecosystem: models.EcosystemNpm},
		{Path: "/a/go.mod", Ecosystem: models.EcosystemGo},
		{Path: "/a/package-lock.json", Ecosystem: models.EcosystemNpm}, // duplicate
	}

	ecosystems := DetectedEcosystems(manifests)

	expected := []models.Ecosystem{models.EcosystemCargo, models.EcosystemNpm, models.EcosystemGo}
	if len(ecosystems) != len(expected) {
		t.Fatalf("expected %d ecosystems, got %d", len(expected), len(ecosystems))
	}

	for i, e := range expected {
		if ecosystems[i] != e {
			t.Errorf("position %d: expected %q, got %q", i, e, ecosystems[i])
		}
	}
}

func TestDetectedEcosystems_SingleEcosystem(t *testing.T) {
	manifests := []DetectedManifest{
		{Path: "/a/package.json", Ecosystem: models.EcosystemNpm},
		{Path: "/b/package-lock.json", Ecosystem: models.EcosystemNpm},
	}

	ecosystems := DetectedEcosystems(manifests)
	if len(ecosystems) != 1 {
		t.Fatalf("expected 1 ecosystem, got %d", len(ecosystems))
	}
	if ecosystems[0] != models.EcosystemNpm {
		t.Errorf("expected %q, got %q", models.EcosystemNpm, ecosystems[0])
	}
}

func TestDetect_ManifestMapCoversAllEntries(t *testing.T) {
	// Verify the manifest map has the expected number of entries to catch regressions.
	expectedCount := 26
	if len(manifestMap) != expectedCount {
		t.Errorf("manifestMap has %d entries, expected %d — update tests if new manifests were added", len(manifestMap), expectedCount)
	}
}

func TestDetect_SkipDirsCoversAllEntries(t *testing.T) {
	expectedCount := 13
	if len(skipDirs) != expectedCount {
		t.Errorf("skipDirs has %d entries, expected %d — update tests if new skip dirs were added", len(skipDirs), expectedCount)
	}
}

func TestDetect_CsprojAlongsideExactMatch(t *testing.T) {
	// Ensure .csproj pattern detection coexists with exact-match packages.config.
	dir := t.TempDir()
	createFile(t, dir, "MyApp.csproj")
	createFile(t, dir, "packages.config")

	manifests, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if len(manifests) != 2 {
		t.Fatalf("expected 2 manifests, got %d", len(manifests))
	}

	// Both should be nuget.
	for _, m := range manifests {
		if m.Ecosystem != models.EcosystemNuget {
			t.Errorf("expected nuget ecosystem, got %q for %q", m.Ecosystem, m.Path)
		}
	}
}

func TestDetect_SkippedDirWithNestedNonSkippedSubdir(t *testing.T) {
	dir := t.TempDir()

	// node_modules/somepackage/lib/ should all be skipped.
	nested := filepath.Join(dir, "node_modules", "somepackage", "lib")
	mustMkdirAll(t, nested)
	createFile(t, nested, "package.json")

	manifests, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if len(manifests) != 0 {
		t.Errorf("expected 0 manifests (all inside node_modules), got %d", len(manifests))
	}
}

// --- helpers ---

func createFile(t *testing.T, dir, name string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatalf("failed to create file %q: %v", path, err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("failed to create directory %q: %v", path, err)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("failed to create directories %q: %v", path, err)
	}
}

