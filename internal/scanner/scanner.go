package scanner

import (
	"github.com/mlw157/GoScan/internal/advisories"
	"github.com/mlw157/GoScan/internal/models"
	"github.com/mlw157/GoScan/internal/parsers"
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

// ScanResult dependencies and vulnerabilities fetched from a file
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
