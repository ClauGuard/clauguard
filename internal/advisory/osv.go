package advisory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ClaudeGuard/claudeguard/pkg/models"
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
			// Parse CVSS vector string or numeric score
			if strings.Contains(score, "CVSS:") {
				// Extract base score from vector — simplified
				return models.SeverityMedium // TODO: parse CVSS vector properly
			}
		}
	}

	// Infer from ID prefix
	id := v.ID
	if strings.HasPrefix(id, "GHSA-") {
		return models.SeverityMedium // conservative default for GitHub advisories
	}

	return models.SeverityUnknown
}

// cleanVersion strips common version prefixes and constraint operators.
func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	// Strip common prefixes
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~")
	v = strings.TrimPrefix(v, ">=")
	v = strings.TrimPrefix(v, "<=")
	v = strings.TrimPrefix(v, "==")
	v = strings.TrimPrefix(v, "~=")
	v = strings.TrimPrefix(v, "!=")
	v = strings.TrimPrefix(v, "~> ")
	return strings.TrimSpace(v)
}
