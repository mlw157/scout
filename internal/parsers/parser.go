package parsers

import "github.com/mlw157/Scout/internal/models"

// Parser this defines services which can parse a dependency file
type Parser interface {
	ParseFile(path string) ([]models.Dependency, error)
}
