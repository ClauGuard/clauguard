package detector

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/kemaldelalic/claudeguard/pkg/models"
)

// manifestMap maps filenames to their ecosystem.
var manifestMap = map[string]models.Ecosystem{
	"package.json":      models.EcosystemNpm,
	"package-lock.json": models.EcosystemNpm,
	"yarn.lock":         models.EcosystemNpm,
	"pnpm-lock.yaml":    models.EcosystemNpm,
	"composer.json":     models.EcosystemComposer,
	"composer.lock":     models.EcosystemComposer,
	"requirements.txt":  models.EcosystemPip,
	"Pipfile":           models.EcosystemPip,
	"Pipfile.lock":      models.EcosystemPip,
	"pyproject.toml":    models.EcosystemPip,
	"poetry.lock":       models.EcosystemPip,
	"go.mod":            models.EcosystemGo,
	"go.sum":            models.EcosystemGo,
	"Cargo.toml":        models.EcosystemCargo,
	"Cargo.lock":        models.EcosystemCargo,
	"Gemfile":           models.EcosystemGem,
	"Gemfile.lock":      models.EcosystemGem,
	"pom.xml":           models.EcosystemMaven,
	"build.gradle":      models.EcosystemGradle,
	"build.gradle.kts":  models.EcosystemGradle,
	"*.csproj":          models.EcosystemNuget,
	"packages.config":   models.EcosystemNuget,
	"Package.swift":     models.EcosystemSwift,
	"Podfile":           models.EcosystemCocoaPod,
	"Podfile.lock":      models.EcosystemCocoaPod,
	"pubspec.yaml":      models.EcosystemPub,
	"pubspec.lock":      models.EcosystemPub,
}

// skipDirs are directories we always skip during detection.
var skipDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	".git":         true,
	".hg":          true,
	".svn":         true,
	"__pycache__":  true,
	".tox":         true,
	".venv":        true,
	"venv":         true,
	"target":       true,
	"build":        true,
	"dist":         true,
	"Pods":         true,
}

// DetectedManifest represents a found dependency manifest file.
type DetectedManifest struct {
	Path      string
	Ecosystem models.Ecosystem
}

// Detect walks the project directory and finds all dependency manifest files.
func Detect(projectPath string) ([]DetectedManifest, error) {
	var manifests []DetectedManifest
	seen := make(map[models.Ecosystem]bool)

	err := filepath.WalkDir(projectPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable paths
		}

		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		name := d.Name()

		// Check exact filename matches
		if eco, ok := manifestMap[name]; ok {
			manifests = append(manifests, DetectedManifest{Path: path, Ecosystem: eco})
			seen[eco] = true
			return nil
		}

		// Check pattern matches (e.g., *.csproj)
		if strings.HasSuffix(name, ".csproj") {
			manifests = append(manifests, DetectedManifest{Path: path, Ecosystem: models.EcosystemNuget})
			seen[models.EcosystemNuget] = true
		}

		return nil
	})

	return manifests, err
}

// DetectedEcosystems returns the unique set of ecosystems found.
func DetectedEcosystems(manifests []DetectedManifest) []models.Ecosystem {
	seen := make(map[models.Ecosystem]bool)
	var result []models.Ecosystem
	for _, m := range manifests {
		if !seen[m.Ecosystem] {
			seen[m.Ecosystem] = true
			result = append(result, m.Ecosystem)
		}
	}
	return result
}
