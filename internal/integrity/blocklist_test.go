package integrity

import (
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestNewChecker_LoadsEmbeddedData(t *testing.T) {
	c := NewChecker()

	// Verify popular names are loaded for each supported ecosystem
	ecosystems := []models.Ecosystem{
		models.EcosystemNpm,
		models.EcosystemPip,
		models.EcosystemComposer,
		models.EcosystemCargo,
		models.EcosystemGem,
		models.EcosystemGo,
	}

	for _, eco := range ecosystems {
		names := c.popular[eco]
		if len(names) == 0 {
			t.Errorf("no popular names loaded for ecosystem %s", eco)
		}
	}

	// Verify normalized indexes are built
	for _, eco := range ecosystems {
		if c.normalizedPopular[eco] == nil {
			t.Errorf("no normalized index for ecosystem %s", eco)
		}
	}

	// Verify blocklist is loaded
	if len(c.blocklist) == 0 {
		t.Error("blocklist is empty after loading")
	}
	if _, ok := c.blocklist["npm"]; !ok {
		t.Error("expected npm entries in blocklist")
	}
}

func TestNewChecker_KnownPopularPackages(t *testing.T) {
	c := NewChecker()

	// Spot-check some packages that should definitely be in the lists
	checks := []struct {
		eco  models.Ecosystem
		name string
	}{
		{models.EcosystemNpm, "lodash"},
		{models.EcosystemNpm, "express"},
		{models.EcosystemNpm, "react"},
		{models.EcosystemPip, "requests"},
		{models.EcosystemPip, "numpy"},
		{models.EcosystemComposer, "symfony/console"},
		{models.EcosystemCargo, "serde"},
		{models.EcosystemGem, "rails"},
		{models.EcosystemGem, "rake"},
	}

	for _, tc := range checks {
		if !c.popular[tc.eco][tc.name] {
			t.Errorf("expected %q to be in popular %s packages", tc.name, tc.eco)
		}
	}
}

func TestNewChecker_BlocklistEntries(t *testing.T) {
	c := NewChecker()

	// "crossenv" is the classic npm typosquat
	npmList := c.blocklist["npm"]
	if npmList == nil {
		t.Fatal("npm blocklist not loaded")
	}
	entry, ok := npmList["crossenv"]
	if !ok {
		t.Fatal("expected 'crossenv' in npm blocklist")
	}
	if entry.Target != "cross-env" {
		t.Errorf("crossenv target = %q, want %q", entry.Target, "cross-env")
	}
}

func TestNewChecker_EndToEnd(t *testing.T) {
	c := NewChecker()

	// A known typosquat should be detected
	deps := []models.Dependency{
		{Name: "crossenv", Ecosystem: models.EcosystemNpm},
	}
	issues := c.Check(deps)
	if len(issues) == 0 {
		t.Error("expected issues for known typosquat 'crossenv'")
	}
	if issues[0].Type != "known_typosquat" {
		t.Errorf("expected known_typosquat, got %s", issues[0].Type)
	}
}
