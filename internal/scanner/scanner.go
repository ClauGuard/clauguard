package scanner

import (
	"github.com/ClaudeGuard/claudeguard/internal/detector"
	"github.com/ClaudeGuard/claudeguard/pkg/models"
)

// Parser extracts dependencies from a manifest file.
type Parser interface {
	Parse(manifestPath string) ([]models.Dependency, error)
	Ecosystem() models.Ecosystem
}

// registry holds parsers keyed by ecosystem.
var registry = map[models.Ecosystem]Parser{}

// Register adds a parser for an ecosystem.
func Register(p Parser) {
	registry[p.Ecosystem()] = p
}

// ParseAll reads all detected manifests and returns the combined dependency list.
func ParseAll(manifests []detector.DetectedManifest) ([]models.Dependency, error) {
	var all []models.Dependency
	seen := make(map[string]bool)

	for _, m := range manifests {
		p, ok := registry[m.Ecosystem]
		if !ok {
			continue // no parser registered for this ecosystem yet
		}

		deps, err := p.Parse(m.Path)
		if err != nil {
			continue // skip unparseable files, log later
		}

		for _, d := range deps {
			key := string(d.Ecosystem) + ":" + d.Name + ":" + d.Version
			if !seen[key] {
				seen[key] = true
				all = append(all, d)
			}
		}
	}

	return all, nil
}
