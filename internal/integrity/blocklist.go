package integrity

import (
	_ "embed"
	"encoding/json"
)

//go:embed data/known_typosquats.json
var typosquatData []byte

// blocklistEntry represents a single entry in the known_typosquats.json flat array.
type blocklistEntry struct {
	MaliciousPackage string `json:"malicious_package"`
	TargetPackage    string `json:"target_package"`
	Ecosystem        string `json:"ecosystem"`
	Classification   string `json:"classification"`
	Source           string `json:"source"`
}

// ecosystemAliases maps alternative ecosystem names in the dataset to our canonical keys.
var ecosystemAliases = map[string]string{
	"crates.io": "cargo",
}

// loadBlocklist parses the embedded known typosquats JSON into the checker's blocklist.
func (c *Checker) loadBlocklist() {
	var entries []blocklistEntry
	if err := json.Unmarshal(typosquatData, &entries); err != nil {
		return // silently ignore malformed data; the blocklist is a bonus, not required
	}

	for _, e := range entries {
		eco := e.Ecosystem
		if alias, ok := ecosystemAliases[eco]; ok {
			eco = alias
		}

		if c.blocklist[eco] == nil {
			c.blocklist[eco] = make(map[string]knownTyposquat)
		}
		c.blocklist[eco][e.MaliciousPackage] = knownTyposquat{
			Name:           e.MaliciousPackage,
			Target:         e.TargetPackage,
			Classification: e.Classification,
			Source:          e.Source,
		}
	}
}
