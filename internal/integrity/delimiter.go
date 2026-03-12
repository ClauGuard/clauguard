package integrity

import "strings"

// normalizeDelimiters replaces all common delimiters with a single canonical
// form (empty string) for comparison purposes.
func normalizeDelimiters(name string) string {
	r := strings.NewReplacer(
		"-", "",
		"_", "",
		".", "",
	)
	return r.Replace(name)
}

// checkDelimiterConfusion checks if the dependency name differs from a popular
// package only by delimiter characters (hyphen, underscore, dot).
// Returns the matched popular package name, or empty string if no match.
func checkDelimiterConfusion(depName string, popularNames map[string]bool, normalizedPopular map[string]string) string {
	normDep := normalizeDelimiters(depName)
	if normDep == "" {
		return ""
	}

	if target, ok := normalizedPopular[normDep]; ok {
		// Only flag if the original names are different
		if target != depName {
			return target
		}
	}
	return ""
}

// buildNormalizedIndex creates a map from normalized names to their original forms.
// If multiple popular packages normalize to the same string, the first one wins.
func buildNormalizedIndex(popularNames map[string]bool) map[string]string {
	index := make(map[string]string, len(popularNames))
	for name := range popularNames {
		norm := normalizeDelimiters(name)
		if _, exists := index[norm]; !exists {
			index[norm] = name
		}
	}
	return index
}
