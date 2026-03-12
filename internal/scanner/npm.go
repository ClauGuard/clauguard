package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func init() {
	Register(&NpmParser{})
}

// NpmParser parses package.json and package-lock.json files.
type NpmParser struct{}

func (p *NpmParser) Ecosystem() models.Ecosystem {
	return models.EcosystemNpm
}

type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type packageLockJSON struct {
	Packages map[string]packageLockEntry `json:"packages"`
}

type packageLockEntry struct {
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
}

func (p *NpmParser) Parse(manifestPath string) ([]models.Dependency, error) {
	name := filepath.Base(manifestPath)

	switch name {
	case "package-lock.json":
		return p.parseLockFile(manifestPath)
	case "package.json":
		return p.parsePackageJSON(manifestPath)
	default:
		return nil, nil
	}
}

func (p *NpmParser) parsePackageJSON(path string) ([]models.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var deps []models.Dependency
	for name, version := range pkg.Dependencies {
		deps = append(deps, models.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemNpm,
			Source:    path,
			IsDev:     false,
		})
	}
	for name, version := range pkg.DevDependencies {
		deps = append(deps, models.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemNpm,
			Source:    path,
			IsDev:     true,
		})
	}

	return deps, nil
}

func (p *NpmParser) parseLockFile(path string) ([]models.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock packageLockJSON
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var deps []models.Dependency
	for pkgPath, entry := range lock.Packages {
		if pkgPath == "" {
			continue // root package
		}
		// Extract package name from path like "node_modules/@scope/pkg"
		// Handle nested node_modules by taking the last segment
		name := pkgPath
		if i := strings.LastIndex(pkgPath, "node_modules/"); i >= 0 {
			name = pkgPath[i+len("node_modules/"):]
		}

		deps = append(deps, models.Dependency{
			Name:      name,
			Version:   entry.Version,
			Ecosystem: models.EcosystemNpm,
			Source:    path,
			IsDev:     entry.Dev,
		})
	}

	return deps, nil
}
