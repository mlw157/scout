package detectors

import "github.com/mlw157/Probe/internal/models"

// Detector this defines services which can find dependency files, with options for excluding directories and filtering ecosystems
type Detector interface {
	DetectFiles(root string, excludeDirs []string, ecosystems []string) ([]models.File, error)
}
