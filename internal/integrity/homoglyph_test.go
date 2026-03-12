package integrity

import (
	"testing"
)

func TestHomoglyphVariants(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains []string // expected variants that should be present
		excludes []string // variants that should NOT be present
	}{
		{
			name:     "rn to m",
			input:    "nurnpy",
			contains: []string{"numpy"},
		},
		{
			name:     "m to rn",
			input:    "numpy",
			contains: []string{"nurnpy"},
		},
		{
			name:     "l to 1",
			input:    "loadash",
			contains: []string{"1oadash"},
		},
		{
			name:     "1 to l",
			input:    "1odash",
			contains: []string{"lodash"},
		},
		{
			name:     "0 to o",
			input:    "l0dash",
			contains: []string{"lodash"},
		},
		{
			name:     "vv to w",
			input:    "vvebpack",
			contains: []string{"webpack"},
		},
		{
			name:     "w to vv",
			input:    "webpack",
			contains: []string{"vvebpack"},
		},
		{
			name:     "cl to d",
			input:    "cloadash",
			contains: []string{"doadash"},
		},
		{
			name:     "no match returns empty",
			input:    "zzzzz",
			contains: []string{},
		},
		{
			name:     "identity excluded",
			input:    "abc",
			excludes: []string{"abc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variants := homoglyphVariants(tt.input)
			variantSet := make(map[string]bool)
			for _, v := range variants {
				variantSet[v] = true
			}

			for _, want := range tt.contains {
				if !variantSet[want] {
					t.Errorf("homoglyphVariants(%q) missing expected variant %q, got %v", tt.input, want, variants)
				}
			}
			for _, excluded := range tt.excludes {
				if variantSet[excluded] {
					t.Errorf("homoglyphVariants(%q) should not contain %q", tt.input, excluded)
				}
			}
		})
	}
}

func TestHomoglyphVariantsNoDuplicates(t *testing.T) {
	// "mm" has multiple possible substitutions: m→rn at pos 0 and pos 1
	variants := homoglyphVariants("mm")
	seen := make(map[string]bool)
	for _, v := range variants {
		if seen[v] {
			t.Errorf("duplicate variant %q in homoglyphVariants(\"mm\")", v)
		}
		seen[v] = true
	}
}
