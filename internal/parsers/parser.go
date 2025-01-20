package parsers

import "github.com/mlw157/scout/internal/models"

// Parser this defines services which can parse a dependency file
type Parser interface {
	ParseFile(path string) ([]models.Dependency, error)
}
