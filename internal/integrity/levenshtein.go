package integrity

// levenshtein computes the Levenshtein edit distance between two strings.
func levenshtein(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	// Use single-row optimization: O(min(m,n)) space
	if len(a) > len(b) {
		a, b = b, a
	}

	prev := make([]int, len(a)+1)
	for i := range prev {
		prev[i] = i
	}

	for j := 1; j <= len(b); j++ {
		curr := make([]int, len(a)+1)
		curr[0] = j
		for i := 1; i <= len(a); i++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[i] = min(
				curr[i-1]+1,   // insertion
				prev[i]+1,     // deletion
				prev[i-1]+cost, // substitution
			)
		}
		prev = curr
	}

	return prev[len(a)]
}

// maxEditDistance returns the maximum Levenshtein distance to consider
// as a potential typosquat, based on the target name length.
func maxEditDistance(nameLen int) int {
	switch {
	case nameLen <= 3:
		return 0 // too short, skip entirely
	case nameLen <= 6:
		return 1
	case nameLen <= 14:
		return 2
	default:
		return 3
	}
}
