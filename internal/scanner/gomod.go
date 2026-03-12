package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func init() {
	Register(&GoModParser{})
}

// GoModParser parses go.mod files.
type GoModParser struct{}

func (p *GoModParser) Ecosystem() models.Ecosystem {
	return models.EcosystemGo
}

func (p *GoModParser) Parse(manifestPath string) ([]models.Dependency, error) {
	name := filepath.Base(manifestPath)
	if name != "go.mod" {
		return nil, nil // skip go.sum, we parse go.mod which is authoritative
	}

	file, err := os.Open(manifestPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []models.Dependency
	inRequire := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		// Single-line require
		if strings.HasPrefix(line, "require ") && !strings.Contains(line, "(") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				deps = append(deps, models.Dependency{
					Name:      parts[1],
					Version:   parts[2],
					Ecosystem: models.EcosystemGo,
					Source:    manifestPath,
				})
			}
			continue
		}

		// Multi-line require block
		if inRequire {
			// Skip comments and indirect markers
			cleanLine := line
			if idx := strings.Index(cleanLine, "//"); idx >= 0 {
				cleanLine = strings.TrimSpace(cleanLine[:idx])
			}
			parts := strings.Fields(cleanLine)
			if len(parts) >= 2 {
				deps = append(deps, models.Dependency{
					Name:      parts[0],
					Version:   parts[1],
					Ecosystem: models.EcosystemGo,
					Source:    manifestPath,
					IsDev:     false, // Go indirect deps are still production deps
				})
			}
		}
	}

	return deps, scanner.Err()
}
