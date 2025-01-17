package parsers

import "github.com/mlw157/GoScan/internal/models"

// ParserService this defines services which can parse a dependency file
type ParserService interface {
	ParseFile(path string) ([]models.Dependency, error)
}

// ParseFile this is currently redundant, but can be useful in the future for standardizing logging etc
func ParseFile(parser ParserService, path string) ([]models.Dependency, error) {
	dependencies, err := parser.ParseFile(path)
	if err != nil {
		return nil, err
	}

	return dependencies, nil
}
