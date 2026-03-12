package integrity

import (
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

// newTestChecker creates a checker with controlled test data instead of embedded files.
func newTestChecker(popular map[models.Ecosystem]map[string]bool, blocklist map[string]map[string]knownTyposquat) *Checker {
	c := &Checker{
		popular:           popular,
		normalizedPopular: make(map[models.Ecosystem]map[string]string),
		blocklist:         blocklist,
	}

	for eco, names := range c.popular {
		c.normalizedPopular[eco] = buildNormalizedIndex(names)
	}

	return c
}

func TestCheck_PopularPackagesSkipped(t *testing.T) {
	popular := map[models.Ecosystem]map[string]bool{
		models.EcosystemNpm: {"lodash": true, "express": true},
	}
	c := newTestChecker(popular, nil)

	deps := []models.Dependency{
		{Name: "lodash", Ecosystem: models.EcosystemNpm},
		{Name: "express", Ecosystem: models.EcosystemNpm},
	}

	issues := c.Check(deps)
	if len(issues) != 0 {
		t.Errorf("expected no issues for popular packages, got %d", len(issues))
	}
}

func TestCheck_UnknownEcosystemSkipped(t *testing.T) {
	popular := map[models.Ecosystem]map[string]bool{
		models.EcosystemNpm: {"lodash": true},
	}
	c := newTestChecker(popular, nil)

	deps := []models.Dependency{
		{Name: "some-pkg", Ecosystem: models.EcosystemMaven}, // no popular data for maven
	}

	issues := c.Check(deps)
	if len(issues) != 0 {
		t.Errorf("expected no issues for unknown ecosystem, got %d", len(issues))
	}
}

func TestCheck_LevenshteinDetection(t *testing.T) {
	popular := map[models.Ecosystem]map[string]bool{
		models.EcosystemNpm: {"express": true, "lodash": true},
	}
	c := newTestChecker(popular, nil)

	deps := []models.Dependency{
		{Name: "expres", Ecosystem: models.EcosystemNpm}, // edit distance 1 from "express"
	}

	issues := c.Check(deps)

	found := false
	for _, issue := range issues {
		if issue.Type == "typosquat_candidate" && issue.Dependency == "expres" {
			found = true
			if issue.Severity != models.SeverityHigh {
				t.Errorf("expected high severity for distance 1, got %s", issue.Severity)
			}
		}
	}
	if !found {
		t.Error("expected typosquat_candidate issue for 'expres'")
	}
}

func TestCheck_HomoglyphDetection(t *testing.T) {
	popular := map[models.Ecosystem]map[string]bool{
		models.EcosystemNpm: {"lodash": true},
	}
	c := newTestChecker(popular, nil)

	deps := []models.Dependency{
		{Name: "1odash", Ecosystem: models.EcosystemNpm}, // l→1 homoglyph
	}

	issues := c.Check(deps)

	found := false
	for _, issue := range issues {
		if issue.Type == "homoglyph_candidate" {
			found = true
			if issue.Severity != models.SeverityHigh {
				t.Errorf("expected high severity for homoglyph, got %s", issue.Severity)
			}
		}
	}
	if !found {
		t.Error("expected homoglyph_candidate issue for '1odash'")
	}
}

func TestCheck_DelimiterConfusion(t *testing.T) {
	popular := map[models.Ecosystem]map[string]bool{
		models.EcosystemNpm: {"date-fns": true},
	}
	c := newTestChecker(popular, nil)

	deps := []models.Dependency{
		{Name: "date_fns", Ecosystem: models.EcosystemNpm},
	}

	issues := c.Check(deps)

	found := false
	for _, issue := range issues {
		if issue.Type == "delimiter_confusion" {
			found = true
			if issue.Severity != models.SeverityMedium {
				t.Errorf("expected medium severity for delimiter confusion, got %s", issue.Severity)
			}
		}
	}
	if !found {
		t.Error("expected delimiter_confusion issue for 'date_fns'")
	}
}

func TestCheck_Combosquat(t *testing.T) {
	popular := map[models.Ecosystem]map[string]bool{
		models.EcosystemNpm: {"express": true},
	}
	c := newTestChecker(popular, nil)

	deps := []models.Dependency{
		{Name: "express-js", Ecosystem: models.EcosystemNpm},
	}

	issues := c.Check(deps)

	found := false
	for _, issue := range issues {
		if issue.Type == "combosquat_candidate" {
			found = true
			if issue.Severity != models.SeverityLow {
				t.Errorf("expected low severity for combosquat, got %s", issue.Severity)
			}
		}
	}
	if !found {
		t.Error("expected combosquat_candidate issue for 'express-js'")
	}
}

func TestCheck_KnownBlocklist(t *testing.T) {
	popular := map[models.Ecosystem]map[string]bool{
		models.EcosystemNpm: {"cross-env": true},
	}
	blocklist := map[string]map[string]knownTyposquat{
		"npm": {
			"crossenv": {
				Name:           "crossenv",
				Target:         "cross-env",
				Classification: "data_exfiltration",
				Source:          "npm_advisory",
			},
		},
	}
	c := newTestChecker(popular, blocklist)

	deps := []models.Dependency{
		{Name: "crossenv", Ecosystem: models.EcosystemNpm},
	}

	issues := c.Check(deps)

	if len(issues) != 1 {
		t.Fatalf("expected exactly 1 issue for known typosquat, got %d", len(issues))
	}
	if issues[0].Type != "known_typosquat" {
		t.Errorf("expected type known_typosquat, got %s", issues[0].Type)
	}
	if issues[0].Severity != models.SeverityCritical {
		t.Errorf("expected critical severity, got %s", issues[0].Severity)
	}
}

func TestCheck_BlocklistShortCircuits(t *testing.T) {
	// When a dep is on the blocklist, other checks should not run
	popular := map[models.Ecosystem]map[string]bool{
		models.EcosystemNpm: {"cross-env": true},
	}
	blocklist := map[string]map[string]knownTyposquat{
		"npm": {
			"crossenv": {
				Name:           "crossenv",
				Target:         "cross-env",
				Classification: "data_exfiltration",
				Source:          "npm_advisory",
			},
		},
	}
	c := newTestChecker(popular, blocklist)

	deps := []models.Dependency{
		{Name: "crossenv", Ecosystem: models.EcosystemNpm},
	}

	issues := c.Check(deps)

	// Should only have the blocklist issue, not also levenshtein/delimiter
	if len(issues) != 1 {
		t.Errorf("expected 1 issue (blocklist short-circuits), got %d: %+v", len(issues), issues)
	}
}

func TestCheck_Deduplication(t *testing.T) {
	popular := map[models.Ecosystem]map[string]bool{
		models.EcosystemNpm: {"express": true},
	}
	c := newTestChecker(popular, nil)

	// Same dep twice
	deps := []models.Dependency{
		{Name: "expres", Ecosystem: models.EcosystemNpm},
		{Name: "expres", Ecosystem: models.EcosystemNpm},
	}

	issues := c.Check(deps)

	typeCount := make(map[string]int)
	for _, issue := range issues {
		typeCount[issue.Type]++
	}

	for typ, count := range typeCount {
		if count > 1 {
			t.Errorf("duplicate issue type %q: appeared %d times", typ, count)
		}
	}
}

func TestCheck_ScopedPackage(t *testing.T) {
	popular := map[models.Ecosystem]map[string]bool{
		models.EcosystemNpm: {"lodash": true},
	}
	c := newTestChecker(popular, nil)

	deps := []models.Dependency{
		{Name: "@evil/1odash", Ecosystem: models.EcosystemNpm}, // scoped, base = "1odash", homoglyph of "lodash"
	}

	issues := c.Check(deps)

	found := false
	for _, issue := range issues {
		if issue.Type == "homoglyph_candidate" {
			found = true
		}
	}
	if !found {
		t.Error("expected homoglyph detection to work through scoped package name")
	}
}

func TestCheck_MultipleIssueTypes(t *testing.T) {
	// A dep can trigger multiple non-blocklist checks
	popular := map[models.Ecosystem]map[string]bool{
		models.EcosystemPip: {"numpy": true},
	}
	c := newTestChecker(popular, nil)

	// "nurnpy" is homoglyph of numpy (rn→m) and also levenshtein distance 1 from numpy
	deps := []models.Dependency{
		{Name: "nurnpy", Ecosystem: models.EcosystemPip},
	}

	issues := c.Check(deps)
	types := make(map[string]bool)
	for _, issue := range issues {
		types[issue.Type] = true
	}

	if !types["homoglyph_candidate"] {
		t.Error("expected homoglyph_candidate for 'nurnpy'")
	}
}

func TestExtractBaseName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"lodash", "lodash"},
		{"@babel/core", "core"},
		{"@scope/package", "package"},
		{"symfony/console", "console"},
		{"deep/nested/pkg", "pkg"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractBaseName(tt.input)
			if got != tt.want {
				t.Errorf("extractBaseName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEcosystemToBlocklistKey(t *testing.T) {
	tests := []struct {
		eco  models.Ecosystem
		want string
	}{
		{models.EcosystemNpm, "npm"},
		{models.EcosystemPip, "pypi"},
		{models.EcosystemComposer, "packagist"},
		{models.EcosystemCargo, "cargo"},
		{models.EcosystemGem, "rubygems"},
		{models.EcosystemGo, "go"},
		{models.EcosystemMaven, ""},
		{models.EcosystemSwift, ""},
	}

	for _, tt := range tests {
		t.Run(string(tt.eco), func(t *testing.T) {
			got := ecosystemToBlocklistKey(tt.eco)
			if got != tt.want {
				t.Errorf("ecosystemToBlocklistKey(%q) = %q, want %q", tt.eco, got, tt.want)
			}
		})
	}
}
