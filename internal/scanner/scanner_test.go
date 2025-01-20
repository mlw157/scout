package scanner_test

import (
	"github.com/mlw157/Scout/internal/models"
	"testing"
)

type MockParserService struct {
	parseFileFunction func(path string) ([]models.Dependency, error)
}

func (m *MockParserService) ParseFile(path string) ([]models.Dependency, error) {
	return m.parseFileFunction(path)
}

type MockAdvisoryService struct {
	fetchVulnerabilitiesFunction func(dependencies []models.Dependency) ([]models.Vulnerability, error)
}

func (m *MockAdvisoryService) FetchVulnerabilities(dependencies []models.Dependency) ([]models.Vulnerability, error) {
	return m.fetchVulnerabilitiesFunction(dependencies)
}

// todo make tests (not sure what to test yet since Scanner is essentially a service that orchestrates a parser and advisory together, it doesn't have testable business logic
func TestScanFile(t *testing.T) {

}
