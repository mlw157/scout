package gh

import (
	"encoding/json"
	"github.com/mlw157/scout/internal/models"
	"io"
	"net/http"
	"net/url"
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

// buildAffectsParam api.github.com/advisories parameter "affects" accepts a string of dependencies with versions seperated by commas
func buildAffectsParam(dependencies []models.Dependency) string {
	dependencyList := ""
	for _, dependency := range dependencies {
		dependencyList += dependency.Name + "@" + dependency.Version + ","
	}
	return strings.Trim(dependencyList, ",")
}

func (s *GitHubAdvisoryService) FetchVulnerabilities(dependencies []models.Dependency) ([]models.Vulnerability, error) {
	if len(dependencies) == 0 {
		return nil, nil
	}
	var allVulnerabilities []models.Vulnerability

	//todo fix possible pagination issue since it only can response with 100 vulnerabilities at once

	// separate dependencies into batches in order to not go above uri length limit
	const batchSize = 50
	for i := 0; i < len(dependencies); i += batchSize {
		end := i + batchSize
		if end > len(dependencies) {
			end = len(dependencies)
		}

		batch := dependencies[i:end]
		affectsParam := buildAffectsParam(batch)

		requestURL := s.BaseURL + "?affects=" + url.QueryEscape(affectsParam) + "&ecosystem=" + url.QueryEscape(dependencies[0].Ecosystem)

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

		vulnerabilities, err := s.ParseResponse(resp.Body, batch)
		resp.Body.Close()

		if err != nil {
			return nil, err
		}

		allVulnerabilities = append(allVulnerabilities, vulnerabilities...)

	}

	return allVulnerabilities, nil
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
