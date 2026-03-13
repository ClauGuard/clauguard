package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func init() {
	Register(&CocoaPodsParser{})
}

// CocoaPodsParser parses Podfile and Podfile.lock files.
type CocoaPodsParser struct{}

func (p *CocoaPodsParser) Ecosystem() models.Ecosystem {
	return models.EcosystemCocoaPod
}

func (p *CocoaPodsParser) Parse(manifestPath string) ([]models.Dependency, error) {
	name := filepath.Base(manifestPath)

	switch name {
	case "Podfile.lock":
		return p.parseLockFile(manifestPath)
	case "Podfile":
		return p.parsePodfile(manifestPath)
	default:
		return nil, nil
	}
}

func (p *CocoaPodsParser) parsePodfile(path string) ([]models.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []models.Dependency
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Match: pod 'Name', '~> 1.0'
		if !strings.HasPrefix(line, "pod ") {
			continue
		}

		line = strings.TrimPrefix(line, "pod ")
		parts := strings.SplitN(line, ",", 3)
		name := strings.Trim(strings.TrimSpace(parts[0]), `'"`)

		version := "*"
		if len(parts) >= 2 {
			version = strings.Trim(strings.TrimSpace(parts[1]), `'"`)
		}

		deps = append(deps, models.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemCocoaPod,
			Source:    path,
		})
	}

	return deps, scanner.Err()
}

func (p *CocoaPodsParser) parseLockFile(path string) ([]models.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []models.Dependency
	scanner := bufio.NewScanner(file)
	inPods := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "PODS:" {
			inPods = true
			continue
		}

		if inPods {
			// Top-level pods are indented with "  - Name (version)"
			// Sub-dependencies are indented further with "    - Name"
			if len(line) >= 2 && line[0] == ' ' && line[1] == ' ' {
				if len(line) >= 4 && line[2] == ' ' && line[3] == ' ' {
					// Sub-dependency, skip
					continue
				}
				// Top-level pod: "  - Name (version)"
				entry := strings.TrimPrefix(trimmed, "- ")
				name, version := parsePodEntry(entry)
				if name != "" {
					deps = append(deps, models.Dependency{
						Name:      name,
						Version:   version,
						Ecosystem: models.EcosystemCocoaPod,
						Source:    path,
					})
				}
			} else if len(trimmed) > 0 && trimmed[0] != ' ' {
				// New section
				inPods = false
			}
		}
	}

	return deps, scanner.Err()
}

// parsePodEntry parses "Name (1.2.3)" into name and version.
func parsePodEntry(entry string) (string, string) {
	idx := strings.Index(entry, " (")
	if idx == -1 {
		return entry, ""
	}
	name := entry[:idx]
	version := strings.TrimRight(entry[idx+2:], "):")
	return name, version
}
