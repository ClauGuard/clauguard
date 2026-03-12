package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/ClaudeGuard/claudeguard/pkg/models"
)

func init() {
	Register(&ComposerParser{})
}

// ComposerParser parses composer.json and composer.lock files.
type ComposerParser struct{}

func (p *ComposerParser) Ecosystem() models.Ecosystem {
	return models.EcosystemComposer
}

type composerJSON struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

type composerLock struct {
	Packages    []composerLockPackage `json:"packages"`
	PackagesDev []composerLockPackage `json:"packages-dev"`
}

type composerLockPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	License []string `json:"license"`
}

func (p *ComposerParser) Parse(manifestPath string) ([]models.Dependency, error) {
	name := filepath.Base(manifestPath)

	switch name {
	case "composer.lock":
		return p.parseLockFile(manifestPath)
	case "composer.json":
		return p.parseComposerJSON(manifestPath)
	default:
		return nil, nil
	}
}

func (p *ComposerParser) parseComposerJSON(path string) ([]models.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var comp composerJSON
	if err := json.Unmarshal(data, &comp); err != nil {
		return nil, err
	}

	var deps []models.Dependency
	for name, version := range comp.Require {
		if name == "php" || isPhpExtension(name) {
			continue
		}
		deps = append(deps, models.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemComposer,
			Source:    path,
			IsDev:     false,
		})
	}
	for name, version := range comp.RequireDev {
		deps = append(deps, models.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemComposer,
			Source:    path,
			IsDev:     true,
		})
	}

	return deps, nil
}

func (p *ComposerParser) parseLockFile(path string) ([]models.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var deps []models.Dependency
	for _, pkg := range lock.Packages {
		deps = append(deps, models.Dependency{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: models.EcosystemComposer,
			Source:    path,
			IsDev:     false,
		})
	}
	for _, pkg := range lock.PackagesDev {
		deps = append(deps, models.Dependency{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: models.EcosystemComposer,
			Source:    path,
			IsDev:     true,
		})
	}

	return deps, nil
}

func isPhpExtension(name string) bool {
	return len(name) > 4 && name[:4] == "ext-"
}
