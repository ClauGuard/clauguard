package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func init() {
	Register(&PubParser{})
}

// PubParser parses pubspec.yaml and pubspec.lock files.
type PubParser struct{}

func (p *PubParser) Ecosystem() models.Ecosystem {
	return models.EcosystemPub
}

func (p *PubParser) Parse(manifestPath string) ([]models.Dependency, error) {
	name := filepath.Base(manifestPath)

	switch name {
	case "pubspec.lock":
		return p.parseLockFile(manifestPath)
	case "pubspec.yaml":
		return p.parsePubspec(manifestPath)
	default:
		return nil, nil
	}
}

func (p *PubParser) parsePubspec(path string) ([]models.Dependency, error) {
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
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Top-level keys (no indentation)
		if len(line) > 0 && line[0] != ' ' && line[0] != '#' {
			switch {
			case strings.HasPrefix(trimmed, "dependencies:"):
				inDeps = true
				isDev = false
			case strings.HasPrefix(trimmed, "dev_dependencies:"):
				inDeps = true
				isDev = true
			default:
				inDeps = false
			}
			continue
		}

		if !inDeps || trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Indented dependency line: "  package_name: ^1.0.0" or "  package_name:"
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 2 {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) != 2 {
				continue
			}

			name := strings.TrimSpace(parts[0])
			version := strings.TrimSpace(parts[1])

			// Skip dependency_overrides-style or empty (hosted/git/path deps)
			if version == "" || strings.HasPrefix(version, "{") {
				version = "*"
			}

			deps = append(deps, models.Dependency{
				Name:      name,
				Version:   version,
				Ecosystem: models.EcosystemPub,
				Source:    path,
				IsDev:     isDev,
			})
		}
	}

	return deps, scanner.Err()
}

func (p *PubParser) parseLockFile(path string) ([]models.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []models.Dependency
	scanner := bufio.NewScanner(file)
	inPackages := false
	var currentName string
	var currentVersion string
	isDev := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Top-level "packages:" section
		if trimmed == "packages:" {
			inPackages = true
			continue
		}

		if !inPackages {
			continue
		}

		// New top-level section ends packages
		if len(line) > 0 && line[0] != ' ' {
			inPackages = false
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))

		// Package name at indent 2: "  package_name:"
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			// Flush previous package
			if currentName != "" {
				deps = append(deps, models.Dependency{
					Name:      currentName,
					Version:   currentVersion,
					Ecosystem: models.EcosystemPub,
					Source:    path,
					IsDev:     isDev,
				})
			}
			currentName = strings.TrimSuffix(trimmed, ":")
			currentVersion = ""
			isDev = false
			continue
		}

		// Properties at indent 4+
		if indent >= 4 && currentName != "" {
			if strings.HasPrefix(trimmed, "version:") {
				currentVersion = strings.Trim(strings.TrimPrefix(trimmed, "version:"), ` "`)
			}
			if strings.HasPrefix(trimmed, "dependency:") {
				dep := strings.Trim(strings.TrimPrefix(trimmed, "dependency:"), ` "`)
				isDev = strings.Contains(dep, "dev") || dep == "transitive"
			}
		}
	}

	// Flush last package
	if currentName != "" {
		deps = append(deps, models.Dependency{
			Name:      currentName,
			Version:   currentVersion,
			Ecosystem: models.EcosystemPub,
			Source:    path,
			IsDev:     isDev,
		})
	}

	return deps, scanner.Err()
}
