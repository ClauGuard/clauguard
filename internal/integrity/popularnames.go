package integrity

import (
	"bufio"
	"bytes"
	_ "embed"
	"strings"

	"github.com/ClauGuard/clauguard/pkg/models"
)

//go:embed data/npm.txt
var npmData []byte

//go:embed data/pypi.txt
var pypiData []byte

//go:embed data/packagist.txt
var packagistData []byte

//go:embed data/cargo.txt
var cargoData []byte

//go:embed data/rubygems.txt
var rubygemsData []byte

//go:embed data/go.txt
var goData []byte

// loadPopularNames loads all embedded popular package name lists into the checker.
func (c *Checker) loadPopularNames() {
	ecosystemData := map[models.Ecosystem][]byte{
		models.EcosystemNpm:      npmData,
		models.EcosystemPip:      pypiData,
		models.EcosystemComposer: packagistData,
		models.EcosystemCargo:    cargoData,
		models.EcosystemGem:      rubygemsData,
		models.EcosystemGo:       goData,
	}

	for eco, data := range ecosystemData {
		c.popular[eco] = parseNameList(data)
	}
}

// parseNameList reads a newline-delimited list of package names into a set.
func parseNameList(data []byte) map[string]bool {
	names := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if name != "" && !strings.HasPrefix(name, "#") {
			names[name] = true
		}
	}
	return names
}
