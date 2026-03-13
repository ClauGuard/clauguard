package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func init() {
	Register(&SwiftParser{})
}

// SwiftParser parses Package.swift files.
type SwiftParser struct{}

func (p *SwiftParser) Ecosystem() models.Ecosystem {
	return models.EcosystemSwift
}

func (p *SwiftParser) Parse(manifestPath string) ([]models.Dependency, error) {
	name := filepath.Base(manifestPath)
	if name != "Package.swift" {
		return nil, nil
	}

	file, err := os.Open(manifestPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []models.Dependency
	scanner := bufio.NewScanner(file)

	// Match .package(url: "https://github.com/org/repo", from: "1.0.0")
	// Match .package(url: "https://github.com/org/repo.git", .upToNextMajor(from: "2.0.0"))
	// Match .package(url: "https://github.com/org/repo", exact: "1.2.3")
	urlRe := regexp.MustCompile(`\.package\s*\(\s*url:\s*"([^"]+)"`)
	fromRe := regexp.MustCompile(`from:\s*"([^"]+)"`)
	exactRe := regexp.MustCompile(`exact:\s*"([^"]+)"`)

	for scanner.Scan() {
		line := scanner.Text()

		urlMatch := urlRe.FindStringSubmatch(line)
		if urlMatch == nil {
			continue
		}

		url := urlMatch[1]
		name := extractSwiftPackageName(url)

		version := "*"
		if m := fromRe.FindStringSubmatch(line); m != nil {
			version = m[1]
		} else if m := exactRe.FindStringSubmatch(line); m != nil {
			version = m[1]
		}

		deps = append(deps, models.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemSwift,
			Source:    manifestPath,
		})
	}

	return deps, scanner.Err()
}

// extractSwiftPackageName extracts a package name from a git URL.
// "https://github.com/apple/swift-argument-parser.git" -> "apple/swift-argument-parser"
func extractSwiftPackageName(url string) string {
	url = strings.TrimSuffix(url, ".git")
	// Try to extract org/repo from common hosts
	for _, prefix := range []string{"https://github.com/", "https://gitlab.com/", "https://bitbucket.org/"} {
		if strings.HasPrefix(url, prefix) {
			return strings.TrimPrefix(url, prefix)
		}
	}
	// Fallback: last two path components
	parts := strings.Split(strings.TrimRight(url, "/"), "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "/" + parts[len(parts)-1]
	}
	return url
}
