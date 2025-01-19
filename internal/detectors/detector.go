package detectors

import "github.com/mlw157/GoScan/internal/models"

// Detector this defines services which can find dependency files
type Detector interface {
	DetectFiles(root string) ([]models.File, error)
}
