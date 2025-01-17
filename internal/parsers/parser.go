package parsers

import "github.com/mlw157/GoScan/internal/models"

// ParserService this defines services which can parse a dependency file
type ParserService interface {
	ParseFile(path string) ([]models.Dependency, error)
}
