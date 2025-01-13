package analyzer

import (
	"github.com/mlw157/GoScan/internal/advisories"
	"github.com/mlw157/GoScan/internal/models"
)

// AnalyzeDependencies given a service such as GitHub Advisory, get vulnerable dependencies
func AnalyzeDependencies(service advisories.AdvisoryService, dependencies []models.Dependency) ([]models.Vulnerability, error) {
	vulnerabilities, err := service.FetchVulnerabilities(dependencies)

	if err != nil {
		return nil, err
	}

	return vulnerabilities, nil
}
