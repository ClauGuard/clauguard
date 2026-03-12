package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/ClaudeGuard/claudeguard/pkg/models"
)

func init() {
	Register(&CargoParser{})
}

// CargoParser parses Cargo.toml and Cargo.lock files.
type CargoParser struct{}

func (p *CargoParser) Ecosystem() models.Ecosystem {
	return models.EcosystemCargo
}

func (p *CargoParser) Parse(manifestPath string) ([]models.Dependency, error) {
	name := filepath.Base(manifestPath)

	switch name {
	case "Cargo.lock":
		return p.parseLockFile(manifestPath)
	case "Cargo.toml":
		return p.parseCargoToml(manifestPath)
	default:
		return nil, nil
	}
}

func (p *CargoParser) parseCargoToml(path string) ([]models.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []models.Dependency
	scanner := bufio.NewScanner(file)
	inDeps := false
	isDev := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[dependencies]" {
			inDeps = true
			isDev = false
			continue
		}
		if line == "[dev-dependencies]" || line == "[dev_dependencies]" {
			inDeps = true
			isDev = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inDeps = false
			continue
		}

		if !inDeps || line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		versionStr := strings.TrimSpace(parts[1])

		// Handle inline table: package = { version = "1.0", features = [...] }
		version := extractCargoVersion(versionStr)

		deps = append(deps, models.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemCargo,
			Source:    path,
			IsDev:     isDev,
		})
	}

	return deps, scanner.Err()
}

func (p *CargoParser) parseLockFile(path string) ([]models.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []models.Dependency
	scanner := bufio.NewScanner(file)
	var currentName, currentVersion string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			if currentName != "" {
				deps = append(deps, models.Dependency{
					Name:      currentName,
					Version:   currentVersion,
					Ecosystem: models.EcosystemCargo,
					Source:    path,
				})
			}
			currentName = ""
			currentVersion = ""
			continue
		}

		if strings.HasPrefix(line, "name = ") {
			currentName = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		}
		if strings.HasPrefix(line, "version = ") {
			currentVersion = strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
		}
	}

	// Don't forget the last package
	if currentName != "" {
		deps = append(deps, models.Dependency{
			Name:      currentName,
			Version:   currentVersion,
			Ecosystem: models.EcosystemCargo,
			Source:    path,
		})
	}

	return deps, scanner.Err()
}

func extractCargoVersion(s string) string {
	s = strings.TrimSpace(s)
	// Simple string version: "1.0"
	if strings.HasPrefix(s, `"`) {
		return strings.Trim(s, `"`)
	}
	// Inline table: { version = "1.0", ... }
	if strings.HasPrefix(s, "{") {
		parts := strings.Split(s, ",")
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				key := strings.Trim(strings.TrimSpace(kv[0]), "{ ")
				if key == "version" {
					return strings.Trim(strings.TrimSpace(kv[1]), `"} `)
				}
			}
		}
	}
	return s
}
