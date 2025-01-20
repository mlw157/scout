package gh

import (
	"encoding/json"
	"errors"
	"github.com/mlw157/scout/internal/models"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type GitHubAdvisoryService struct {
	BaseURL    string
	HTTPClient *http.Client
	Token      string // Optional GitHub Auth token (it increases hourly api requests from 60 to 5000)
}

func NewGitHubAdvisoryService(token string) *GitHubAdvisoryService {
	return &GitHubAdvisoryService{
		BaseURL:    "https://api.github.com/advisories",
		HTTPClient: &http.Client{},
		Token:      token,
	}
}

func (s *GitHubAdvisoryService) FetchVulnerabilities(dependencies []models.Dependency) ([]models.Vulnerability, error) {

	if len(dependencies) == 0 {
		return nil, nil
	}
	
	// todo fix pagination (if dependencies len() exceeds 100) (github api per_page param has a max of 100)

	affectsParam := buildAffectsParam(dependencies)
	dependenciesLength := strconv.Itoa(len(dependencies))

	// assuming all dependencies are same ecosystem
	requestURL := s.BaseURL + "?affects=" + affectsParam + "&ecosystem=" + dependencies[0].Ecosystem + "&per_page=" + dependenciesLength

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}

	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}

	resp, err := s.HTTPClient.Do(req)
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

	// for now, I'm assuming vulnerabilities array only has one element, I don't understand why gh api even returns this as an array? doesn't make sense
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

// buildAffectsParam api.github.com/advisories parameter "affects" accepts a string of dependencies with versions seperated by commas
func buildAffectsParam(dependencies []models.Dependency) string {
	dependencyList := ""
	for _, dependency := range dependencies {
		dependencyList += dependency.Name + "@" + dependency.Version + ","
	}
	return strings.Trim(dependencyList, ",")
}
