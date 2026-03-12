package advisory

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClauGuard/clauguard/pkg/models"
)

func TestCleanVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"prefix v", "v1.2.3", "1.2.3"},
		{"prefix caret", "^1.2.3", "1.2.3"},
		{"prefix tilde", "~1.2.3", "1.2.3"},
		{"prefix >=", ">=1.2.3", "1.2.3"},
		{"prefix <=", "<=1.2.3", "1.2.3"},
		{"prefix ==", "==1.2.3", "1.2.3"},
		{"prefix ~=", "~=1.2.3", "1.2.3"},
		{"prefix !=", "!=1.2.3", "1.2.3"},
		{"prefix ~> with space", "~> 1.2.3", "1.2.3"},
		{"already clean", "1.2.3", "1.2.3"},
		{"empty string", "", ""},
		{"wildcard star", "*", "*"},
		{"whitespace only", "   ", ""},
		{"leading trailing whitespace", "  1.2.3  ", "1.2.3"},
		{"v prefix with whitespace", "  v2.0.0  ", "2.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanVersion(tt.input)
			if got != tt.want {
				t.Errorf("cleanVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSeverityFromScore(t *testing.T) {
	tests := []struct {
		name  string
		score float64
		want  models.Severity
	}{
		{"critical 10.0", 10.0, models.SeverityCritical},
		{"critical 9.8", 9.8, models.SeverityCritical},
		{"critical boundary 9.0", 9.0, models.SeverityCritical},
		{"high 8.9", 8.9, models.SeverityHigh},
		{"high 7.5", 7.5, models.SeverityHigh},
		{"high boundary 7.0", 7.0, models.SeverityHigh},
		{"medium 6.9", 6.9, models.SeverityMedium},
		{"medium 5.0", 5.0, models.SeverityMedium},
		{"medium boundary 4.0", 4.0, models.SeverityMedium},
		{"low 3.9", 3.9, models.SeverityLow},
		{"low 2.0", 2.0, models.SeverityLow},
		{"low boundary 0.1", 0.1, models.SeverityLow},
		{"unknown zero", 0.0, models.SeverityUnknown},
		{"unknown negative", -1.0, models.SeverityUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := severityFromScore(tt.score)
			if got != tt.want {
				t.Errorf("severityFromScore(%v) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}

func TestComputeCVSSv3BaseScore(t *testing.T) {
	tests := []struct {
		name     string
		vector   string
		wantOK   bool
		wantScore float64
		wantSev  models.Severity // for cross-checking severity mapping
	}{
		{
			name:      "critical 9.8 - network no auth",
			vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantOK:    true,
			wantScore: 9.8,
			wantSev:   models.SeverityCritical,
		},
		{
			name:      "medium 6.1 - scope changed XSS",
			vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			wantOK:    true,
			wantScore: 6.1,
			wantSev:   models.SeverityMedium,
		},
		{
			name:      "low 3.3 - local info disclosure",
			vector:    "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
			wantOK:    true,
			wantScore: 3.3,
			wantSev:   models.SeverityLow,
		},
		{
			name:   "invalid - missing metrics",
			vector: "CVSS:3.1/AV:N/AC:L",
			wantOK: false,
		},
		{
			name:   "invalid - empty string",
			vector: "",
			wantOK: false,
		},
		{
			name:   "invalid - bad AV value",
			vector: "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantOK: false,
		},
		{
			name:   "invalid - bad scope value",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",
			wantOK: false,
		},
		{
			name:      "zero impact - all none",
			vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			wantOK:    true,
			wantScore: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, ok := computeCVSSv3BaseScore(tt.vector)
			if ok != tt.wantOK {
				t.Fatalf("computeCVSSv3BaseScore(%q) ok = %v, want %v", tt.vector, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if score != tt.wantScore {
				t.Errorf("computeCVSSv3BaseScore(%q) = %v, want %v", tt.vector, score, tt.wantScore)
			}
			if tt.wantSev != "" {
				gotSev := severityFromScore(score)
				if gotSev != tt.wantSev {
					t.Errorf("severityFromScore(%v) = %q, want %q", score, gotSev, tt.wantSev)
				}
			}
		})
	}
}

func TestRoundUp(t *testing.T) {
	tests := []struct {
		name string
		val  float64
		want float64
	}{
		{"rounds up fractional", 4.02, 4.1},
		{"exact tenth stays", 4.0, 4.0},
		{"rounds up to next tenth", 9.85, 9.9},
		{"zero stays zero", 0.0, 0.0},
		{"already at tenth", 7.3, 7.3},
		{"tiny fraction rounds up", 5.001, 5.1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := roundUp(tt.val)
			if got != tt.want {
				t.Errorf("roundUp(%v) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name string
		vuln osvVulnerability
		want models.Severity
	}{
		{
			name: "direct numeric score",
			vuln: osvVulnerability{
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: "9.8"},
				},
			},
			want: models.SeverityCritical,
		},
		{
			name: "CVSS vector string",
			vuln: osvVulnerability{
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				},
			},
			want: models.SeverityCritical,
		},
		{
			name: "non-CVSS_V3 type ignored falls back to GHSA",
			vuln: osvVulnerability{
				ID: "GHSA-xxxx-yyyy-zzzz",
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V2", Score: "7.5"},
				},
			},
			want: models.SeverityMedium,
		},
		{
			name: "GHSA prefix with no severity info",
			vuln: osvVulnerability{
				ID: "GHSA-abcd-efgh-ijkl",
			},
			want: models.SeverityMedium,
		},
		{
			name: "no severity info no GHSA prefix",
			vuln: osvVulnerability{
				ID: "CVE-2023-12345",
			},
			want: models.SeverityUnknown,
		},
		{
			name: "multiple severity entries picks CVSS_V3",
			vuln: osvVulnerability{
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V2", Score: "10.0"},
					{Type: "CVSS_V3", Score: "4.5"},
				},
			},
			want: models.SeverityMedium,
		},
		{
			name: "low numeric score",
			vuln: osvVulnerability{
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: "2.1"},
				},
			},
			want: models.SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSeverity(tt.vuln)
			if got != tt.want {
				t.Errorf("parseSeverity() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConvertVuln(t *testing.T) {
	dep := models.Dependency{
		Name:      "lodash",
		Version:   "4.17.15",
		Ecosystem: models.EcosystemNpm,
		Source:     "package-lock.json",
	}

	v := osvVulnerability{
		ID:      "GHSA-xxxx-yyyy-zzzz",
		Aliases: []string{"CVE-2020-12345"},
		Summary: "Prototype pollution in lodash",
		Details: "Lodash versions prior to 4.17.21 are vulnerable.",
		Severity: []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		}{
			{Type: "CVSS_V3", Score: "7.5"},
		},
		Affected: []struct {
			Ranges []struct {
				Events []struct {
					Fixed string `json:"fixed,omitempty"`
				} `json:"events"`
			} `json:"ranges"`
		}{
			{
				Ranges: []struct {
					Events []struct {
						Fixed string `json:"fixed,omitempty"`
					} `json:"events"`
				}{
					{
						Events: []struct {
							Fixed string `json:"fixed,omitempty"`
						}{
							{Fixed: "4.17.21"},
							{Fixed: ""},
						},
					},
				},
			},
		},
		References: []struct {
			URL string `json:"url"`
		}{
			{URL: "https://github.com/lodash/lodash/issues/1"},
			{URL: "https://nvd.nist.gov/vuln/detail/CVE-2020-12345"},
		},
	}

	result := convertVuln(v, dep)

	if result.ID != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("ID = %q, want %q", result.ID, "GHSA-xxxx-yyyy-zzzz")
	}
	if len(result.Aliases) != 1 || result.Aliases[0] != "CVE-2020-12345" {
		t.Errorf("Aliases = %v, want [CVE-2020-12345]", result.Aliases)
	}
	if result.Summary != "Prototype pollution in lodash" {
		t.Errorf("Summary = %q, want %q", result.Summary, "Prototype pollution in lodash")
	}
	if result.Details != "Lodash versions prior to 4.17.21 are vulnerable." {
		t.Errorf("Details mismatch")
	}
	if result.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q, want %q", result.Severity, models.SeverityHigh)
	}
	if result.Dependency != "lodash" {
		t.Errorf("Dependency = %q, want %q", result.Dependency, "lodash")
	}
	if result.Ecosystem != models.EcosystemNpm {
		t.Errorf("Ecosystem = %q, want %q", result.Ecosystem, models.EcosystemNpm)
	}
	if len(result.FixVersions) != 1 || result.FixVersions[0] != "4.17.21" {
		t.Errorf("FixVersions = %v, want [4.17.21]", result.FixVersions)
	}
	if len(result.References) != 2 {
		t.Errorf("References count = %d, want 2", len(result.References))
	}
}

func TestConvertVuln_NoFixVersions(t *testing.T) {
	dep := models.Dependency{Name: "foo", Version: "1.0.0", Ecosystem: models.EcosystemNpm}
	v := osvVulnerability{ID: "CVE-2023-1", Summary: "test"}

	result := convertVuln(v, dep)

	if result.FixVersions != nil {
		t.Errorf("FixVersions = %v, want nil", result.FixVersions)
	}
	if result.References != nil {
		t.Errorf("References = %v, want nil", result.References)
	}
}

func TestQueryBatch_EmptyDeps(t *testing.T) {
	client := NewOSVClient()
	vulns, err := client.QueryBatch(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vulns != nil {
		t.Errorf("expected nil, got %v", vulns)
	}

	vulns, err = client.QueryBatch([]models.Dependency{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vulns != nil {
		t.Errorf("expected nil, got %v", vulns)
	}
}

func TestQueryBatch_AllWildcardVersions(t *testing.T) {
	client := NewOSVClient()
	deps := []models.Dependency{
		{Name: "foo", Version: "*", Ecosystem: models.EcosystemNpm},
		{Name: "bar", Version: "", Ecosystem: models.EcosystemNpm},
	}
	vulns, err := client.QueryBatch(deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vulns != nil {
		t.Errorf("expected nil, got %v", vulns)
	}
}

func TestQueryBatch_UnknownEcosystem(t *testing.T) {
	client := NewOSVClient()
	deps := []models.Dependency{
		{Name: "foo", Version: "1.0.0", Ecosystem: models.EcosystemSwift},
		{Name: "bar", Version: "2.0.0", Ecosystem: models.EcosystemCocoaPod},
	}
	vulns, err := client.QueryBatch(deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vulns != nil {
		t.Errorf("expected nil for unknown ecosystems, got %v", vulns)
	}
}

func TestQueryBatch_SuccessfulResponse(t *testing.T) {
	resp := osvBatchResponse{
		Results: []struct {
			Vulns []osvVulnerability `json:"vulns"`
		}{
			{
				Vulns: []osvVulnerability{
					{
						ID:      "GHSA-test-0001",
						Summary: "Test vulnerability",
						Severity: []struct {
							Type  string `json:"type"`
							Score string `json:"score"`
						}{
							{Type: "CVSS_V3", Score: "7.5"},
						},
					},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json content type, got %s", r.Header.Get("Content-Type"))
		}

		var req osvBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}
		if len(req.Queries) != 1 {
			t.Errorf("expected 1 query, got %d", len(req.Queries))
		}
		if req.Queries[0].Package.Name != "lodash" {
			t.Errorf("expected package name lodash, got %s", req.Queries[0].Package.Name)
		}
		if req.Queries[0].Package.Ecosystem != "npm" {
			t.Errorf("expected ecosystem npm, got %s", req.Queries[0].Package.Ecosystem)
		}
		if req.Queries[0].Version != "4.17.15" {
			t.Errorf("expected version 4.17.15, got %s", req.Queries[0].Version)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := newTestClient(server.URL)
	deps := []models.Dependency{
		{Name: "lodash", Version: "4.17.15", Ecosystem: models.EcosystemNpm},
	}

	vulns, err := client.QueryBatch(deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if vulns[0].ID != "GHSA-test-0001" {
		t.Errorf("vuln ID = %q, want %q", vulns[0].ID, "GHSA-test-0001")
	}
	if vulns[0].Severity != models.SeverityHigh {
		t.Errorf("vuln severity = %q, want %q", vulns[0].Severity, models.SeverityHigh)
	}
	if vulns[0].Dependency != "lodash" {
		t.Errorf("vuln dependency = %q, want %q", vulns[0].Dependency, "lodash")
	}
}

func TestQueryBatch_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	client := newTestClient(server.URL)
	deps := []models.Dependency{
		{Name: "lodash", Version: "4.17.15", Ecosystem: models.EcosystemNpm},
	}

	_, err := client.QueryBatch(deps)
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
	if got := err.Error(); got == "" {
		t.Error("expected non-empty error message")
	}
}

func TestQueryBatch_NetworkError(t *testing.T) {
	// Use a server that is immediately closed to simulate network error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close()

	client := newTestClient(server.URL)
	deps := []models.Dependency{
		{Name: "lodash", Version: "4.17.15", Ecosystem: models.EcosystemNpm},
	}

	_, err := client.QueryBatch(deps)
	if err == nil {
		t.Fatal("expected error for network failure")
	}
}

func TestQueryBatch_SkipsMixedDeps(t *testing.T) {
	// Mix of valid, unknown ecosystem, and wildcard versions
	resp := osvBatchResponse{
		Results: []struct {
			Vulns []osvVulnerability `json:"vulns"`
		}{
			{Vulns: nil}, // no vulns for the one valid dep
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req osvBatchRequest
		json.NewDecoder(r.Body).Decode(&req)
		// Only the valid npm dep should be queried
		if len(req.Queries) != 1 {
			t.Errorf("expected 1 query (filtered), got %d", len(req.Queries))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := newTestClient(server.URL)
	deps := []models.Dependency{
		{Name: "valid-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNpm},
		{Name: "unknown-eco", Version: "1.0.0", Ecosystem: models.EcosystemSwift},
		{Name: "wildcard", Version: "*", Ecosystem: models.EcosystemNpm},
		{Name: "empty-ver", Version: "", Ecosystem: models.EcosystemNpm},
	}

	vulns, err := client.QueryBatch(deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns, got %d", len(vulns))
	}
}

func TestQueryBatch_VersionCleaned(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req osvBatchRequest
		json.NewDecoder(r.Body).Decode(&req)
		if len(req.Queries) != 1 {
			t.Errorf("expected 1 query, got %d", len(req.Queries))
		} else if req.Queries[0].Version != "1.2.3" {
			t.Errorf("expected cleaned version 1.2.3, got %s", req.Queries[0].Version)
		}
		resp := osvBatchResponse{
			Results: []struct {
				Vulns []osvVulnerability `json:"vulns"`
			}{
				{Vulns: nil},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := newTestClient(server.URL)
	deps := []models.Dependency{
		{Name: "foo", Version: "^1.2.3", Ecosystem: models.EcosystemNpm},
	}
	_, err := client.QueryBatch(deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// newTestClient creates an OSVClient that points at the given test server URL
// instead of the real OSV API. It patches osvAPIURL by replacing the client's
// internal HTTP transport.
func newTestClient(baseURL string) *OSVClient {
	client := NewOSVClient()
	// We can't easily override the const URL, so we wrap the transport to redirect.
	client.httpClient.Transport = &rewriteTransport{
		base:    http.DefaultTransport,
		target:  baseURL,
		original: osvAPIURL,
	}
	return client
}

// rewriteTransport rewrites requests destined for the OSV API to the test server.
type rewriteTransport struct {
	base     http.RoundTripper
	target   string
	original string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the OSV API URL with our test server URL
	req.URL.Scheme = "http"
	req.URL.Host = stripScheme(t.target)
	return t.base.RoundTrip(req)
}

func stripScheme(url string) string {
	if idx := len("http://"); len(url) > idx && url[:idx] == "http://" {
		return url[idx:]
	}
	if idx := len("https://"); len(url) > idx && url[:idx] == "https://" {
		return url[idx:]
	}
	return url
}
