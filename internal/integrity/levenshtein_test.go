package integrity

import "testing"

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"", "abc", 3},
		{"abc", "", 3},
		{"abc", "abc", 0},
		{"kitten", "sitting", 3},
		{"saturday", "sunday", 3},
		{"lodash", "lodahs", 2}, // transposition = 2 edits in Levenshtein
		{"express", "expres", 1},
		{"react", "recat", 2},
		{"numpy", "numpi", 1},
		{"a", "b", 1},
		{"ab", "ba", 2},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := levenshtein(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestLevenshteinSymmetry(t *testing.T) {
	pairs := [][2]string{
		{"kitten", "sitting"},
		{"express", "expres"},
		{"lodash", "lodahs"},
	}
	for _, p := range pairs {
		ab := levenshtein(p[0], p[1])
		ba := levenshtein(p[1], p[0])
		if ab != ba {
			t.Errorf("levenshtein(%q, %q)=%d != levenshtein(%q, %q)=%d", p[0], p[1], ab, p[1], p[0], ba)
		}
	}
}

func TestMaxEditDistance(t *testing.T) {
	tests := []struct {
		nameLen int
		want    int
	}{
		{0, 0},
		{1, 0},
		{3, 0},
		{4, 1},
		{6, 1},
		{7, 2},
		{14, 2},
		{15, 3},
		{30, 3},
	}

	for _, tt := range tests {
		got := maxEditDistance(tt.nameLen)
		if got != tt.want {
			t.Errorf("maxEditDistance(%d) = %d, want %d", tt.nameLen, got, tt.want)
		}
	}
}
