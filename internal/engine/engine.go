package engine

import (
	"github.com/mlw157/Probe/internal/advisories/gh"
	"github.com/mlw157/Probe/internal/detectors"
	"github.com/mlw157/Probe/internal/factories"
	"github.com/mlw157/Probe/internal/models"
	"github.com/mlw157/Probe/internal/scanner"
)

// Engine will orchestrate scanners with a detector, essentially detecting files and passing them to the correct scanner
type Engine struct {
	detector detectors.Detector
	scanners map[string]*scanner.Scanner // pointer in case we need to alter scanner values such as parser
	config   Config
}

var scannerFactory = factories.NewScannerFactory()

type Config struct {
	Ecosystems   []string // if user specifies ecosystems to scan, default should be all
	ExcludeFiles []string
	OutputFormat string // json, txt, etc
}

func NewEngine(detector detectors.Detector, config Config) *Engine {
	return &Engine{
		detector: detector,
		scanners: make(map[string]*scanner.Scanner),
		config:   config,
	}
}

// Scan detects files, create scanners for the found ecosystems and scans them
func (e *Engine) Scan(root string) ([]*models.ScanResult, error) {
	var scanResults []*models.ScanResult

	files, err := e.detector.DetectFiles(root, e.config.ExcludeFiles, e.config.Ecosystems)

	if err != nil {
		return nil, err
	}

	for _, file := range files {
		s, err := e.populateScanners(file)

		if err != nil {
			return nil, err
		}

		scanResult, err := s.ScanFile(file.Path)

		if err != nil {
			return nil, err
		}

		scanResults = append(scanResults, scanResult)
	}

	return scanResults, nil
}

// todo don't use default advisory
// if a scanner for the file ecosystem doesn't exist yet, make it and add it to map, for now we use default scanners (gh advisory)
func (e *Engine) populateScanners(file models.File) (*scanner.Scanner, error) {
	s, exists := e.scanners[file.Ecosystem]

	if !exists {
		newScanner, err := scannerFactory.CreateScanner(file.Ecosystem, gh.NewGitHubAdvisoryService())
		if err != nil {
			return nil, err
		}
		e.scanners[file.Ecosystem] = newScanner
	}

	return s, nil
}
