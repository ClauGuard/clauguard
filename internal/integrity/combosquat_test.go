package integrity

import "testing"

func TestCheckCombosquat(t *testing.T) {
	popular := map[string]bool{
		"express": true,
		"lodash":  true,
		"react":   true,
		"axios":   true,
		"chalk":   true,
	}

	tests := []struct {
		name    string
		depName string
		want    string
	}{
		// Suffix matches
		{"suffix -js", "express-js", "express"},
		{"suffix -cli", "lodash-cli", "lodash"},
		{"suffix -utils", "react-utils", "react"},
		{"suffix -sdk", "axios-sdk", "axios"},
		{"suffix -official", "express-official", "express"},
		{"suffix 2", "lodash2", "lodash"},

		// Prefix matches
		{"prefix node-", "node-express", "express"},
		{"prefix get-", "get-lodash", "lodash"},
		{"prefix my-", "my-react", "react"},

		// No match cases
		{"exact popular name", "express", ""},
		{"no match", "totally-different", ""},
		{"too short dep", "ab", ""},
		{"short candidate after strip", "a-js", ""}, // "a" < 5 chars

		// chalk is exactly 5 chars, so it matches the >= 5 threshold
		{"chalk suffix", "chalk-js", "chalk"},
		{"chalk cli suffix", "chalk-cli", "chalk"},

		// Not in popular list
		{"not popular suffix", "foobar-js", ""},
		{"not popular prefix", "node-foobar", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkCombosquat(tt.depName, popular)
			if got != tt.want {
				t.Errorf("checkCombosquat(%q) = %q, want %q", tt.depName, got, tt.want)
			}
		})
	}
}
