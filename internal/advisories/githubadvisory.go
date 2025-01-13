package advisories

import (
	"encoding/json"
	"errors"
	"github.com/mlw157/GoScan/internal/models"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type GitHubAdvisoryService struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewGitHubAdvisoryService() *GitHubAdvisoryService {
	return &GitHubAdvisoryService{
		BaseURL:    "https://api.github.com/advisories",
		HTTPClient: &http.Client{},
	}
}

// FetchVulnerabilities
func (s *GitHubAdvisoryService) FetchVulnerabilities(dependencies []models.Dependency) ([]models.Vulnerability, error) {
	// todo fix pagination (if dependencies len() exceeds 100)
	affectsParam := buildAffectsParam(dependencies)
	dependenciesLength := strconv.Itoa(len(dependencies))

	requestURL := s.BaseURL + "?affects=" + affectsParam + "&ecosystem=" + dependencies[0].Language + "&per_page=" + dependenciesLength

	resp, err := s.HTTPClient.Get(requestURL)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch vulnerabilities" + resp.Status)
	}

	// todo parse response and make vulnerabilities (refactor!!!!)
	var apiResponse []struct {
		CVE             string `json:"cve_id"`
		Description     string `json:"description"`
		Severity        string `json:"severity"`
		Vulnerabilities []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			VulnerableVersionRange string `json:"vulnerable_version_range"`
		} `json:"vulnerabilities"`
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(bodyBytes, &apiResponse); err != nil {
		return nil, err
	}
	var vulnerabilities []models.Vulnerability
	for _, item := range apiResponse {
		for _, vuln := range item.Vulnerabilities {
			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Dependency: models.Dependency{
					Name: vuln.Package.Name,
				},
				CVE:              item.CVE,
				Description:      item.Description,
				Severity:         item.Severity,
				AffectedVersions: vuln.VulnerableVersionRange,
			})
		}
	}

	return vulnerabilities, nil

}

// buildAffectsParam api.github.com/advisories parameter "affects" accepts a string of dependencies with versions
func buildAffectsParam(dependencies []models.Dependency) string {
	dependencyList := ""
	for _, dependency := range dependencies {
		dependencyList += dependency.Name + "@" + dependency.Version + ", "
	}
	return strings.Trim(dependencyList, ", ")
}
