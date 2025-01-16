package gh

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

func (s *GitHubAdvisoryService) FetchVulnerabilities(dependencies []models.Dependency) ([]models.Vulnerability, error) {
	// todo fix pagination (if dependencies len() exceeds 100)
	affectsParam := buildAffectsParam(dependencies)
	dependenciesLength := strconv.Itoa(len(dependencies))

	// assuming all dependencies are same ecosystem
	requestURL := s.BaseURL + "?affects=" + affectsParam + "&ecosystem=" + dependencies[0].Language + "&per_page=" + dependenciesLength

	resp, err := s.HTTPClient.Get(requestURL)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch vulnerabilities" + resp.Status)
	}

	vulnerabilities, err := s.ParseResponse(resp.Body, dependencies)
	if err != nil {
		return nil, err
	}

	return vulnerabilities, nil
}

func (s *GitHubAdvisoryService) ParseResponse(body io.Reader, dependencies []models.Dependency) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}

	var responses []Response
	if err := json.Unmarshal(bodyBytes, &responses); err != nil {
		return nil, err
	}

	dependencyMap := make(map[string]models.Dependency)

	// using a map so that it only iterates through all dependencies once
	for _, dependency := range dependencies {
		dependencyMap[dependency.Name] = dependency
	}

	// for now i'm assuming vulnerabilities array only has one element, I don't understand why gh api even returns this as an array? doesn't make sense
	for _, res := range responses {
		dependency := dependencyMap[res.Vulnerabilities[0].Package.Name]
		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			Dependency:             dependency,
			Severity:               res.Severity,
			CVE:                    res.CVE,
			Summary:                res.Summary,
			Description:            res.Summary,
			URL:                    res.URL,
			VulnerableVersionRange: res.Vulnerabilities[0].VulnerableVersionRange,
			FirstPatchedVersion:    res.Vulnerabilities[0].FirstPatchedVersion,
			References:             res.References,
			VulnerableFunctions:    res.Vulnerabilities[0].VulnerableFunctions,
		})
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
