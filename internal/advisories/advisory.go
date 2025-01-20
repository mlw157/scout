package advisories

import "github.com/mlw157/Scout/internal/models"

// AdvisoryService this defines services which can fetch vulnerabilities given dependencies (such as GitHub advisory api)
type AdvisoryService interface {
	FetchVulnerabilities(dependencies []models.Dependency) ([]models.Vulnerability, error)
}
