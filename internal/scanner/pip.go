package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func init() {
	Register(&PipParser{})
}

// PipParser parses requirements.txt and pyproject.toml files.
type PipParser struct{}

func (p *PipParser) Ecosystem() models.Ecosystem {
	return models.EcosystemPip
}

func (p *PipParser) Parse(manifestPath string) ([]models.Dependency, error) {
	name := filepath.Base(manifestPath)

	switch name {
	case "requirements.txt":
		return p.parseRequirementsTxt(manifestPath)
	case "pyproject.toml":
		return p.parsePyprojectToml(manifestPath)
	default:
		return nil, nil
	}
}

func (p *PipParser) parseRequirementsTxt(path string) ([]models.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []models.Dependency
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments, empty lines, and options
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Handle different version specifiers: ==, >=, <=, ~=, !=
		name, version := parseRequirement(line)
		if name == "" {
			continue
		}

		deps = append(deps, models.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemPip,
			Source:    path,
		})
	}

	return deps, scanner.Err()
}

func (p *PipParser) parsePyprojectToml(path string) ([]models.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Simple TOML parsing for dependencies array
	// Full TOML parsing will be added with a proper library
	var deps []models.Dependency
	lines := strings.Split(string(data), "\n")
	inDeps := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "dependencies = [" {
			inDeps = true
			continue
		}
		if inDeps && trimmed == "]" {
			inDeps = false
			continue
		}
		if inDeps {
			// Remove quotes and trailing comma
			dep := strings.Trim(trimmed, `"',`)
			name, version := parseRequirement(dep)
			if name != "" {
				deps = append(deps, models.Dependency{
					Name:      name,
					Version:   version,
					Ecosystem: models.EcosystemPip,
					Source:    path,
				})
			}
		}
	}

	return deps, nil
}

// parseRequirement splits a pip requirement string into name and version.
func parseRequirement(req string) (string, string) {
	// Remove extras like package[extra]
	if idx := strings.Index(req, "["); idx >= 0 {
		end := strings.Index(req, "]")
		if end >= 0 {
			req = req[:idx] + req[end+1:]
		}
	}

	// Remove environment markers
	if idx := strings.Index(req, ";"); idx >= 0 {
		req = strings.TrimSpace(req[:idx])
	}

	// Split on version specifiers
	for _, sep := range []string{"==", ">=", "<=", "~=", "!="} {
		if idx := strings.Index(req, sep); idx >= 0 {
			name := strings.TrimSpace(req[:idx])
			version := strings.TrimSpace(req[idx:])
			return name, version
		}
	}

	// No version specified
	name := strings.TrimSpace(req)
	if name == "" {
		return "", ""
	}
	return name, "*"
}
