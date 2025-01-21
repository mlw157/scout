package engine

import (
	"fmt"
	"github.com/mlw157/scout/internal/advisories/gh"
	"github.com/mlw157/scout/internal/detectors"
	"github.com/mlw157/scout/internal/exporters"
	"github.com/mlw157/scout/internal/factories"
	"github.com/mlw157/scout/internal/models"
	"github.com/mlw157/scout/internal/scanner"
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
	Exporter     exporters.Exporter
	Token        string
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
	//fmt.Println(files)

	if err != nil {
		return nil, err
	}

	for _, file := range files {
		s, err := e.PopulateScanners(file)

		if err != nil {
			return nil, err
		}
		fmt.Printf("Scanning %v\n", file.Path)
		scanResult, err := s.ScanFile(file.Path)

		if err != nil {
			//return nil, err
			fmt.Printf("Error scanning file %s: %v\n\n", file.Path, err)
			continue
		}

		scanResults = append(scanResults, scanResult)
	}

	if e.config.Exporter != nil {
		if err := e.config.Exporter.Export(scanResults); err != nil {
			return nil, fmt.Errorf("failed to export results: %v", err)
		}
	}

	return scanResults, nil
}

// PopulateScanners if a scanner for the file ecosystem doesn't exist yet, make it and add it to map, for now we use default scanners (gh advisory)
// todo don't use default advisory
func (e *Engine) PopulateScanners(file models.File) (*scanner.Scanner, error) {
	s, exists := e.scanners[file.Ecosystem]

	if !exists {
		newScanner, err := scannerFactory.CreateScanner(file.Ecosystem, gh.NewGitHubAdvisoryService(e.config.Token))
		if err != nil {
			return nil, err
		}
		e.scanners[file.Ecosystem] = newScanner

		return newScanner, nil
	}

	return s, nil
}
