package exporters

import "github.com/mlw157/Scout/internal/models"

// Exporter this defines services which export scan results
type Exporter interface {
	Export(results []*models.ScanResult) error
}
