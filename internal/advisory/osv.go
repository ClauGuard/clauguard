package advisory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ClauGuard/clauguard/pkg/models"
)

const osvAPIURL = "https://api.osv.dev/v1/querybatch"

// ecosystemToOSV maps our ecosystem names to OSV ecosystem names.
var ecosystemToOSV = map[models.Ecosystem]string{
	models.EcosystemNpm:      "npm",
	models.EcosystemComposer: "Packagist",
	models.EcosystemPip:      "PyPI",
	models.EcosystemGo:       "Go",
	models.EcosystemCargo:    "crates.io",
	models.EcosystemGem:      "RubyGems",
	models.EcosystemMaven:    "Maven",
	models.EcosystemNuget:    "NuGet",
	models.EcosystemPub:      "Pub",
}

// OSVClient queries the OSV.dev API for known vulnerabilities.
type OSVClient struct {
	httpClient *http.Client
}

// NewOSVClient creates a new OSV API client.
func NewOSVClient() *OSVClient {
	return &OSVClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvVulnerability struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []osvVulnerability `json:"vulns"`
	} `json:"results"`
}

// QueryBatch checks multiple dependencies for vulnerabilities in a single batch request.
func (c *OSVClient) QueryBatch(deps []models.Dependency) ([]models.Vulnerability, error) {
	if len(deps) == 0 {
		return nil, nil
	}

	// Build queries, skip deps without OSV ecosystem mapping or without pinned versions
	var queries []osvQuery
	var queryDeps []models.Dependency // track which dep each query maps to

	for _, dep := range deps {
		osvEco, ok := ecosystemToOSV[dep.Ecosystem]
		if !ok {
			continue
		}
		version := cleanVersion(dep.Version)
		if version == "" || version == "*" {
			continue
		}

		q := osvQuery{Version: version}
		q.Package.Name = dep.Name
		q.Package.Ecosystem = osvEco
		queries = append(queries, q)
		queryDeps = append(queryDeps, dep)
	}

	if len(queries) == 0 {
		return nil, nil
	}

	// OSV batch API has a limit of 1000 queries per request
	var allVulns []models.Vulnerability
	batchSize := 1000

	for i := 0; i < len(queries); i += batchSize {
		end := i + batchSize
		if end > len(queries) {
			end = len(queries)
		}

		vulns, err := c.queryBatchChunk(queries[i:end], queryDeps[i:end])
		if err != nil {
			return allVulns, fmt.Errorf("OSV batch query failed: %w", err)
		}
		allVulns = append(allVulns, vulns...)
	}

	return allVulns, nil
}

func (c *OSVClient) queryBatchChunk(queries []osvQuery, deps []models.Dependency) ([]models.Vulnerability, error) {
	reqBody := osvBatchRequest{Queries: queries}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(osvAPIURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, err
	}

	var vulns []models.Vulnerability
	for i, result := range batchResp.Results {
		if i >= len(deps) {
			break
		}
		dep := deps[i]
		for _, v := range result.Vulns {
			vulns = append(vulns, convertVuln(v, dep))
		}
	}

	return vulns, nil
}

func convertVuln(v osvVulnerability, dep models.Dependency) models.Vulnerability {
	vuln := models.Vulnerability{
		ID:         v.ID,
		Aliases:    v.Aliases,
		Summary:    v.Summary,
		Details:    v.Details,
		Severity:   parseSeverity(v),
		Dependency: dep.Name,
		Ecosystem:  dep.Ecosystem,
	}

	// Extract fix versions
	for _, affected := range v.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					vuln.FixVersions = append(vuln.FixVersions, event.Fixed)
				}
			}
		}
	}

	// Extract references
	for _, ref := range v.References {
		vuln.References = append(vuln.References, ref.URL)
	}

	return vuln
}

func parseSeverity(v osvVulnerability) models.Severity {
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			score := s.Score

			// Try parsing as a direct numeric score first (e.g. "9.8")
			if numScore, err := strconv.ParseFloat(score, 64); err == nil {
				return severityFromScore(numScore)
			}

			// Parse CVSS v3 vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
			if strings.HasPrefix(score, "CVSS:3") {
				if baseScore, ok := computeCVSSv3BaseScore(score); ok {
					return severityFromScore(baseScore)
				}
			}
		}
	}

	// Infer from ID prefix
	if strings.HasPrefix(v.ID, "GHSA-") {
		return models.SeverityMedium // conservative default for GitHub advisories
	}

	return models.SeverityUnknown
}

// severityFromScore maps a CVSS base score to a severity level.
func severityFromScore(score float64) models.Severity {
	switch {
	case score >= 9.0:
		return models.SeverityCritical
	case score >= 7.0:
		return models.SeverityHigh
	case score >= 4.0:
		return models.SeverityMedium
	case score >= 0.1:
		return models.SeverityLow
	default:
		return models.SeverityUnknown
	}
}

// computeCVSSv3BaseScore calculates the CVSS v3.x base score from a vector string.
// Returns the score and true on success, or 0 and false if the vector can't be parsed.
func computeCVSSv3BaseScore(vector string) (float64, bool) {
	metrics := make(map[string]string)
	parts := strings.Split(vector, "/")
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	// Attack Vector
	avValues := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	av, ok := avValues[metrics["AV"]]
	if !ok {
		return 0, false
	}

	// Attack Complexity
	acValues := map[string]float64{"L": 0.77, "H": 0.44}
	ac, ok := acValues[metrics["AC"]]
	if !ok {
		return 0, false
	}

	// Scope
	scopeChanged := metrics["S"] == "C"
	if metrics["S"] != "U" && metrics["S"] != "C" {
		return 0, false
	}

	// Privileges Required (depends on Scope)
	var pr float64
	switch metrics["PR"] {
	case "N":
		pr = 0.85
	case "L":
		if scopeChanged {
			pr = 0.68
		} else {
			pr = 0.62
		}
	case "H":
		if scopeChanged {
			pr = 0.50
		} else {
			pr = 0.27
		}
	default:
		return 0, false
	}

	// User Interaction
	uiValues := map[string]float64{"N": 0.85, "R": 0.62}
	ui, ok := uiValues[metrics["UI"]]
	if !ok {
		return 0, false
	}

	// Impact metrics
	impactValues := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	confImpact, ok := impactValues[metrics["C"]]
	if !ok {
		return 0, false
	}
	integImpact, ok := impactValues[metrics["I"]]
	if !ok {
		return 0, false
	}
	availImpact, ok := impactValues[metrics["A"]]
	if !ok {
		return 0, false
	}

	// Calculate ISS (Impact Sub-Score)
	iss := 1 - ((1 - confImpact) * (1 - integImpact) * (1 - availImpact))

	// If ISS is zero, base score is 0
	if iss <= 0 {
		return 0, true
	}

	// Calculate Impact
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}

	// Calculate Exploitability
	exploitability := 8.22 * av * ac * pr * ui

	// Calculate Base Score
	var baseScore float64
	if scopeChanged {
		baseScore = math.Min(1.08*(impact+exploitability), 10)
	} else {
		baseScore = math.Min(impact+exploitability, 10)
	}

	// Round up to 1 decimal place
	baseScore = roundUp(baseScore)

	return baseScore, true
}

// roundUp rounds a float64 up to 1 decimal place (CVSS spec requires rounding up).
func roundUp(val float64) float64 {
	return math.Ceil(val*10) / 10
}

// cleanVersion strips common version prefixes and constraint operators.
func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	// Strip common prefixes — longer prefixes first to avoid partial matches
	// (e.g., "~=" must be checked before "~", ">=" before ">")
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~> ")
	v = strings.TrimPrefix(v, "~=")
	v = strings.TrimPrefix(v, "~")
	v = strings.TrimPrefix(v, ">=")
	v = strings.TrimPrefix(v, "<=")
	v = strings.TrimPrefix(v, "==")
	v = strings.TrimPrefix(v, "!=")
	return strings.TrimSpace(v)
}
