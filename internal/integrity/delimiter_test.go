package integrity

import "testing"

func TestNormalizeDelimiters(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"lodash", "lodash"},
		{"co-pilot", "copilot"},
		{"co_pilot", "copilot"},
		{"co.pilot", "copilot"},
		{"my-cool_pkg.js", "mycoolpkgjs"},
		{"", ""},
		{"---", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeDelimiters(tt.input)
			if got != tt.want {
				t.Errorf("normalizeDelimiters(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCheckDelimiterConfusion(t *testing.T) {
	popular := map[string]bool{
		"date-fns":       true,
		"lodash":         true,
		"node_modules":   true,
		"my.package":     true,
	}
	index := buildNormalizedIndex(popular)

	tests := []struct {
		name    string
		depName string
		want    string
	}{
		{"hyphen to underscore", "date_fns", "date-fns"},
		{"hyphen to dot", "date.fns", "date-fns"},
		{"underscore to hyphen", "node-modules", "node_modules"},
		{"dot to hyphen", "my-package", "my.package"},
		{"exact match not flagged", "date-fns", ""},
		{"no match", "something-else", ""},
		{"empty input", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkDelimiterConfusion(tt.depName, popular, index)
			if got != tt.want {
				t.Errorf("checkDelimiterConfusion(%q) = %q, want %q", tt.depName, got, tt.want)
			}
		})
	}
}

func TestBuildNormalizedIndex(t *testing.T) {
	popular := map[string]bool{
		"date-fns": true,
		"lodash":   true,
	}
	index := buildNormalizedIndex(popular)

	if _, ok := index["datefns"]; !ok {
		t.Error("expected 'datefns' in normalized index")
	}
	if _, ok := index["lodash"]; !ok {
		t.Error("expected 'lodash' in normalized index")
	}
	if got := index["datefns"]; got != "date-fns" {
		t.Errorf("index[\"datefns\"] = %q, want %q", got, "date-fns")
	}
}
