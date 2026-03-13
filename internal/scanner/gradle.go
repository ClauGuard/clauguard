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
	Register(&GradleParser{})
}

// GradleParser parses build.gradle and build.gradle.kts files.
type GradleParser struct{}

func (p *GradleParser) Ecosystem() models.Ecosystem {
	return models.EcosystemGradle
}

func (p *GradleParser) Parse(manifestPath string) ([]models.Dependency, error) {
	name := filepath.Base(manifestPath)
	switch name {
	case "build.gradle":
		return p.parseGroovy(manifestPath)
	case "build.gradle.kts":
		return p.parseKotlin(manifestPath)
	default:
		return nil, nil
	}
}

// devConfigurations are Gradle configurations considered dev/test-only.
var devConfigurations = map[string]bool{
	"testImplementation":        true,
	"testCompileOnly":           true,
	"testRuntimeOnly":           true,
	"androidTestImplementation": true,
	"testCompile":               true,
	"testRuntime":               true,
}

// Matches: implementation 'group:artifact:version'
// Also: api "group:artifact:version"
var groovyDepRe = regexp.MustCompile(`^\s*(\w+)\s+['"]([^'"]+:[^'"]+:[^'"]+)['"]`)

// Matches: implementation("group:artifact:version")
var kotlinDepRe = regexp.MustCompile(`^\s*(\w+)\s*\(\s*["']([^"']+:[^"']+:[^"']+)["']\s*\)`)

func (p *GradleParser) parseGroovy(path string) ([]models.Dependency, error) {
	return p.parseWithRegex(path, groovyDepRe)
}

func (p *GradleParser) parseKotlin(path string) ([]models.Dependency, error) {
	return p.parseWithRegex(path, kotlinDepRe)
}

func (p *GradleParser) parseWithRegex(path string, re *regexp.Regexp) ([]models.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []models.Dependency
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		matches := re.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		config := matches[1]
		coordinate := matches[2]

		parts := strings.SplitN(coordinate, ":", 3)
		if len(parts) != 3 {
			continue
		}

		deps = append(deps, models.Dependency{
			Name:      parts[0] + ":" + parts[1],
			Version:   parts[2],
			Ecosystem: models.EcosystemGradle,
			Source:    path,
			IsDev:     devConfigurations[config],
		})
	}

	return deps, scanner.Err()
}
