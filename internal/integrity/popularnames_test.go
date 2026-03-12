package integrity

import "testing"

func TestParseNameList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]bool
	}{
		{
			name:  "basic names",
			input: "lodash\nexpress\nreact\n",
			want:  map[string]bool{"lodash": true, "express": true, "react": true},
		},
		{
			name:  "trims whitespace",
			input: "  lodash  \n  express\n",
			want:  map[string]bool{"lodash": true, "express": true},
		},
		{
			name:  "skips blank lines",
			input: "lodash\n\n\nexpress\n",
			want:  map[string]bool{"lodash": true, "express": true},
		},
		{
			name:  "skips comments",
			input: "# popular packages\nlodash\n# more\nexpress\n",
			want:  map[string]bool{"lodash": true, "express": true},
		},
		{
			name:  "empty input",
			input: "",
			want:  map[string]bool{},
		},
		{
			name:  "no trailing newline",
			input: "lodash\nexpress",
			want:  map[string]bool{"lodash": true, "express": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseNameList([]byte(tt.input))
			if len(got) != len(tt.want) {
				t.Errorf("parseNameList() returned %d entries, want %d", len(got), len(tt.want))
			}
			for name := range tt.want {
				if !got[name] {
					t.Errorf("parseNameList() missing %q", name)
				}
			}
		})
	}
}
