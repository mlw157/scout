package scanner

import (
	"github.com/mlw157/scout/internal/advisories"
	"github.com/mlw157/scout/internal/models"
	"github.com/mlw157/scout/internal/parsers"
)

// Scanner given a parser and advisory service, fetch vulnerabilities from a file
type Scanner struct {
	parser   parsers.Parser
	advisory advisories.AdvisoryService
}

func NewScanner(parser parsers.Parser, advisory advisories.AdvisoryService) *Scanner {
	return &Scanner{
		parser:   parser,
		advisory: advisory,
	}
}

// ScanFile fetch dependencies from a file and fetch vulnerabilities
func (s *Scanner) ScanFile(path string) (*models.ScanResult, error) {
	dependencies, err := s.parser.ParseFile(path)
	if err != nil {
		return nil, err
	}

	vulnerabilities, err := s.advisory.FetchVulnerabilities(dependencies)

	if err != nil {
		return nil, err
	}

	return &models.ScanResult{Dependencies: dependencies, Vulnerabilities: vulnerabilities, SourceFile: path}, nil
}
