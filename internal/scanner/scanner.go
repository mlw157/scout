package scanner

import (
	"github.com/mlw157/GoScan/internal/advisories"
	"github.com/mlw157/GoScan/internal/models"
	"github.com/mlw157/GoScan/internal/parsers"
)

type Scanner struct {
	parser   parsers.ParserService
	advisory advisories.AdvisoryService
}

func NewScanner(parser parsers.ParserService, advisory advisories.AdvisoryService) *Scanner {
	return &Scanner{
		parser:   parser,
		advisory: advisory,
	}
}

type ScanResult struct {
	Dependencies    []models.Dependency
	Vulnerabilities []models.Vulnerability
}

// ScanFile fetch dependencies from a file and fetch vulnerabilities
func (s *Scanner) ScanFile(path string) (*ScanResult, error) {
	dependencies, err := s.parser.ParseFile(path)
	if err != nil {
		return nil, err
	}

	vulnerabilities, err := s.advisory.FetchVulnerabilities(dependencies)

	if err != nil {
		return nil, err
	}

	return &ScanResult{Dependencies: dependencies, Vulnerabilities: vulnerabilities}, nil
}
