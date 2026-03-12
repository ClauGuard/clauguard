package integrity

// homoglyphTable maps characters/sequences to their visual lookalikes.
// For each pair, if char A appears in a name, substituting it with char B
// might produce a popular package name (indicating a homoglyph attack).
var homoglyphTable = []struct {
	from string
	to   string
}{
	{"rn", "m"},
	{"m", "rn"},
	{"l", "1"},
	{"1", "l"},
	{"I", "l"},
	{"l", "I"},
	{"0", "O"},
	{"O", "0"},
	{"0", "o"},
	{"o", "0"},
	{"vv", "w"},
	{"w", "vv"},
	{"cl", "d"},
	{"d", "cl"},
	{"nn", "m"},
	{"q", "g"},
	{"g", "q"},
}

// homoglyphVariants generates all single-substitution variants of a name
// using the homoglyph table. Each variant is a name that could be the
// "real" package the attacker is trying to impersonate.
func homoglyphVariants(name string) []string {
	var variants []string
	seen := make(map[string]bool)

	for _, h := range homoglyphTable {
		for i := 0; i <= len(name)-len(h.from); i++ {
			if name[i:i+len(h.from)] == h.from {
				variant := name[:i] + h.to + name[i+len(h.from):]
				if variant != name && !seen[variant] {
					seen[variant] = true
					variants = append(variants, variant)
				}
			}
		}
	}

	return variants
}
