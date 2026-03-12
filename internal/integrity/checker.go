package integrity

import (
	"fmt"
	"strings"

	"github.com/ClauGuard/clauguard/pkg/models"
)

// Checker runs supply chain integrity checks on parsed dependencies.
type Checker struct {
	popular           map[models.Ecosystem]map[string]bool     // popular names per ecosystem
	normalizedPopular map[models.Ecosystem]map[string]string   // delimiter-normalized index
	blocklist         map[string]map[string]knownTyposquat     // ecosystem -> name -> entry
}

// knownTyposquat represents a confirmed typosquat from the embedded dataset.
type knownTyposquat struct {
	Name           string `json:"name"`
	Target         string `json:"target_package"`
	Classification string `json:"classification"`
	Source         string `json:"source"`
}

// NewChecker creates a new integrity checker with embedded data loaded.
func NewChecker() *Checker {
	c := &Checker{
		popular:           make(map[models.Ecosystem]map[string]bool),
		normalizedPopular: make(map[models.Ecosystem]map[string]string),
		blocklist:         make(map[string]map[string]knownTyposquat),
	}

	// Load popular package data
	c.loadPopularNames()

	// Build delimiter-normalized indexes
	for eco, names := range c.popular {
		c.normalizedPopular[eco] = buildNormalizedIndex(names)
	}

	// Load known typosquats blocklist
	c.loadBlocklist()

	return c
}

// Check runs all integrity checks on the given dependencies.
func (c *Checker) Check(deps []models.Dependency) []models.IntegrityIssue {
	var issues []models.IntegrityIssue
	seen := make(map[string]bool) // dedup by dep+type

	for _, dep := range deps {
		popular := c.popular[dep.Ecosystem]
		if popular == nil {
			continue
		}

		// Skip if the dependency itself is in the popular list
		if popular[dep.Name] {
			continue
		}

		depIssues := c.checkDependency(dep, popular)
		for _, issue := range depIssues {
			key := string(issue.Ecosystem) + ":" + issue.Dependency + ":" + issue.Type
			if !seen[key] {
				seen[key] = true
				issues = append(issues, issue)
			}
		}
	}

	return issues
}

func (c *Checker) checkDependency(dep models.Dependency, popular map[string]bool) []models.IntegrityIssue {
	var issues []models.IntegrityIssue
	name := dep.Name

	// For scoped packages (npm @scope/pkg, composer vendor/pkg), extract the package part
	baseName := extractBaseName(name)

	// Pass 1: Known malicious exact match
	if issue := c.checkBlocklist(dep); issue != nil {
		return []models.IntegrityIssue{*issue} // critical, no need to check further
	}

	// Pass 2: Levenshtein distance (classic typosquatting)
	if issue := c.checkLevenshtein(dep, baseName, popular); issue != nil {
		issues = append(issues, *issue)
	}

	// Pass 3: Homoglyph substitution
	if issue := c.checkHomoglyph(dep, baseName, popular); issue != nil {
		issues = append(issues, *issue)
	}

	// Pass 4: Delimiter confusion
	normIndex := c.normalizedPopular[dep.Ecosystem]
	if normIndex != nil {
		if target := checkDelimiterConfusion(baseName, popular, normIndex); target != "" {
			issues = append(issues, models.IntegrityIssue{
				Dependency:  dep.Name,
				Ecosystem:   dep.Ecosystem,
				Type:        "delimiter_confusion",
				Description: fmt.Sprintf("differs from popular package %q only by delimiters", target),
				Severity:    models.SeverityMedium,
			})
		}
	}

	// Pass 5: Combosquatting
	if target := checkCombosquat(baseName, popular); target != "" {
		issues = append(issues, models.IntegrityIssue{
			Dependency:  dep.Name,
			Ecosystem:   dep.Ecosystem,
			Type:        "combosquat_candidate",
			Description: fmt.Sprintf("embeds popular package name %q with suspicious affix", target),
			Severity:    models.SeverityLow,
		})
	}

	return issues
}

func (c *Checker) checkBlocklist(dep models.Dependency) *models.IntegrityIssue {
	ecoName := ecosystemToBlocklistKey(dep.Ecosystem)
	if ecoName == "" {
		return nil
	}

	ecoList := c.blocklist[ecoName]
	if ecoList == nil {
		return nil
	}

	if entry, ok := ecoList[dep.Name]; ok {
		return &models.IntegrityIssue{
			Dependency:  dep.Name,
			Ecosystem:   dep.Ecosystem,
			Type:        "known_typosquat",
			Description: fmt.Sprintf("known typosquat of %q (%s, source: %s)", entry.Target, entry.Classification, entry.Source),
			Severity:    models.SeverityCritical,
		}
	}

	return nil
}

func (c *Checker) checkLevenshtein(dep models.Dependency, baseName string, popular map[string]bool) *models.IntegrityIssue {
	maxDist := maxEditDistance(len(baseName))
	if maxDist == 0 {
		return nil
	}

	var bestMatch string
	bestDist := maxDist + 1

	for popName := range popular {
		// Quick length filter: names with length difference > maxDist can't match
		lenDiff := len(popName) - len(baseName)
		if lenDiff < 0 {
			lenDiff = -lenDiff
		}
		if lenDiff > maxDist {
			continue
		}

		dist := levenshtein(baseName, popName)
		if dist > 0 && dist <= maxDist && dist < bestDist {
			bestDist = dist
			bestMatch = popName
		}
	}

	if bestMatch == "" {
		return nil
	}

	severity := models.SeverityMedium
	if bestDist == 1 {
		severity = models.SeverityHigh
	}

	return &models.IntegrityIssue{
		Dependency:  dep.Name,
		Ecosystem:   dep.Ecosystem,
		Type:        "typosquat_candidate",
		Description: fmt.Sprintf("similar to popular package %q (edit distance %d)", bestMatch, bestDist),
		Severity:    severity,
	}
}

func (c *Checker) checkHomoglyph(dep models.Dependency, baseName string, popular map[string]bool) *models.IntegrityIssue {
	variants := homoglyphVariants(baseName)
	for _, variant := range variants {
		if popular[variant] {
			return &models.IntegrityIssue{
				Dependency:  dep.Name,
				Ecosystem:   dep.Ecosystem,
				Type:        "homoglyph_candidate",
				Description: fmt.Sprintf("uses character substitution resembling popular package %q", variant),
				Severity:    models.SeverityHigh,
			}
		}
	}
	return nil
}

// extractBaseName gets the package name without scope/vendor prefix.
// e.g., "@babel/core" -> "core", "symfony/console" -> "console"
func extractBaseName(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// ecosystemToBlocklistKey maps our ecosystem types to the keys used in the
// known typosquats dataset.
func ecosystemToBlocklistKey(eco models.Ecosystem) string {
	switch eco {
	case models.EcosystemNpm:
		return "npm"
	case models.EcosystemPip:
		return "pypi"
	case models.EcosystemComposer:
		return "packagist"
	case models.EcosystemCargo:
		return "cargo"
	case models.EcosystemGem:
		return "rubygems"
	case models.EcosystemGo:
		return "go"
	default:
		return ""
	}
}
