package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func init() {
	Register(&GemParser{})
}

// GemParser parses Gemfile and Gemfile.lock files.
type GemParser struct{}

func (p *GemParser) Ecosystem() models.Ecosystem {
	return models.EcosystemGem
}

func (p *GemParser) Parse(manifestPath string) ([]models.Dependency, error) {
	name := filepath.Base(manifestPath)

	switch name {
	case "Gemfile.lock":
		return p.parseLockFile(manifestPath)
	case "Gemfile":
		return p.parseGemfile(manifestPath)
	default:
		return nil, nil
	}
}

func (p *GemParser) parseGemfile(path string) ([]models.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []models.Dependency
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if !strings.HasPrefix(line, "gem ") {
			continue
		}

		// gem 'name', '~> 1.0'
		line = strings.TrimPrefix(line, "gem ")
		parts := strings.SplitN(line, ",", 3)
		name := strings.Trim(strings.TrimSpace(parts[0]), `'"`)

		version := "*"
		if len(parts) >= 2 {
			version = strings.Trim(strings.TrimSpace(parts[1]), `'"`)
		}

		deps = append(deps, models.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemGem,
			Source:    path,
		})
	}

	return deps, scanner.Err()
}

func (p *GemParser) parseLockFile(path string) ([]models.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []models.Dependency
	scanner := bufio.NewScanner(file)
	inSpecs := false

	for scanner.Scan() {
		line := scanner.Text()

		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}

		if inSpecs {
			// Gem entries are indented with exactly 4 spaces: "    gem_name (version)"
			if len(line) >= 4 && line[:4] == "    " && (len(line) < 5 || line[4] != ' ') {
				entry := strings.TrimSpace(line)
				parts := strings.SplitN(entry, " ", 2)
				name := parts[0]
				version := ""
				if len(parts) >= 2 {
					version = strings.Trim(parts[1], "()")
				}
				deps = append(deps, models.Dependency{
					Name:      name,
					Version:   version,
					Ecosystem: models.EcosystemGem,
					Source:    path,
				})
			} else if len(line) > 0 && line[0] != ' ' {
				// New section started
				inSpecs = false
			}
		}
	}

	return deps, scanner.Err()
}
