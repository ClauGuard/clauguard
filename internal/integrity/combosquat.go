package integrity

import "strings"

// suspiciousSuffixes are common combosquatting suffixes appended to real package names.
var suspiciousSuffixes = []string{
	"-js", "-node", "-cli", "-utils", "-util", "-helper", "-helpers",
	"-core", "-lib", "-api", "-sdk", "-official", "-real", "-secure",
	"-latest", "-new", "-original", "-dev", "-test", "-beta",
	"2", "3", "-v2", "-v3",
	"js", "node",
}

// suspiciousPrefixes are common combosquatting prefixes prepended to real package names.
var suspiciousPrefixes = []string{
	"node-", "nodejs-", "python-", "py-", "go-", "rust-",
	"get-", "install-", "load-", "my-", "the-", "npm-",
}

// checkCombosquat checks if a dependency name embeds a popular package name
// with a suspicious prefix or suffix.
// Returns the matched popular package name, or empty string if no match.
func checkCombosquat(depName string, popularNames map[string]bool) string {
	// Only check if the dep name is long enough to contain a meaningful package name + affix
	if len(depName) < 6 {
		return ""
	}

	// Don't flag if the dep itself is popular
	if popularNames[depName] {
		return ""
	}

	// Check suffixes: is depName = popularName + suffix?
	for _, suffix := range suspiciousSuffixes {
		if strings.HasSuffix(depName, suffix) {
			candidate := strings.TrimSuffix(depName, suffix)
			if len(candidate) >= 5 && popularNames[candidate] {
				return candidate
			}
		}
	}

	// Check prefixes: is depName = prefix + popularName?
	for _, prefix := range suspiciousPrefixes {
		if strings.HasPrefix(depName, prefix) {
			candidate := strings.TrimPrefix(depName, prefix)
			if len(candidate) >= 5 && popularNames[candidate] {
				return candidate
			}
		}
	}

	return ""
}
