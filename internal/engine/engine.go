package engine

import (
	"fmt"
	"github.com/mlw157/scout/internal/advisories/db"
	"github.com/mlw157/scout/internal/detectors"
	"github.com/mlw157/scout/internal/exporters"
	"github.com/mlw157/scout/internal/factories"
	"github.com/mlw157/scout/internal/models"
	"github.com/mlw157/scout/internal/scanner"
	"log"
	"sync"
)

// Engine will orchestrate scanners with a detector, essentially detecting files and passing them to the correct scanner
type Engine struct {
	detector detectors.Detector
	scanners map[string]*scanner.Scanner // pointer in case we need to alter scanner values such as parser
	config   Config
}

var scannerFactory = factories.NewScannerFactory()

type Config struct {
	Ecosystems     []string // if user specifies ecosystems to scan, default should be all
	ExcludeFiles   []string
	Exporter       exporters.Exporter
	Token          string
	SequentialMode bool
	LatestMode     bool
	DatabasePath   string
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
	err := e.populateScanners()

	if err != nil {
		return nil, err
	}

	// experimental will have goroutines scanning files as they are being found
	if !e.config.SequentialMode {
		var mu sync.Mutex
		var wg sync.WaitGroup

		filesChan, err := e.detector.DetectFilesChannel(root, e.config.ExcludeFiles, e.config.Ecosystems)
		if err != nil {
			return nil, err
		}

		for file := range filesChan {
			// we use a wait group to make sure that the main go routine doesn't exit while a scan is still ongoing (when the file channel closes)
			wg.Add(1)
			go func(f models.File) {
				defer wg.Done()

				s := e.scanners[f.Ecosystem]
				log.Printf("Scanning %v\n", file.Path)
				scanResult, err := s.ScanFile(f.Path)
				if err != nil {
					log.Printf("Could not scan file %s: %v\n", f.Path, err)
					return
				}

				// we need to lock scanResults because if multiple goroutines try to access it at same time it will panic
				mu.Lock()
				scanResults = append(scanResults, scanResult)
				mu.Unlock()
			}(file)
		}

		wg.Wait()

	} else {
		files, err := e.detector.DetectFiles(root, e.config.ExcludeFiles, e.config.Ecosystems)
		if err != nil {
			return nil, err
		}

		for _, file := range files {
			log.Printf("Scanning %v\n", file.Path)
			s := e.scanners[file.Ecosystem]
			scanResult, err := s.ScanFile(file.Path)
			if err != nil {
				log.Printf("\"Could not scan file %s: %v\n", file.Path, err)
				continue
			}
			scanResults = append(scanResults, scanResult)
		}
	}

	if e.config.Exporter != nil {
		log.Printf("Expo")
		if err := e.config.Exporter.Export(scanResults); err != nil {
			return nil, fmt.Errorf("failed to export results: %v", err)
		}
	}

	return scanResults, nil
}

// PopulateScanners if a scanner for the file ecosystem doesn't exist yet, make it and add it to map, for now we use default scanners (database advisory)
// todo don't use default advisory
func (e *Engine) populateScanners() error {
	a, err := db.NewDatabaseAdvisoryService(e.config.DatabasePath, e.config.LatestMode)
	if err != nil {
		return err
	}
	if len(e.config.Ecosystems) > 0 {
		for _, ecosystem := range e.config.Ecosystems {
			_, exists := e.scanners[ecosystem]
			if !exists {
				s, err := scannerFactory.CreateScanner(ecosystem, a)
				if err != nil {
					return err
				}
				e.scanners[ecosystem] = s
			}
		}
	}

	for _, pattern := range detectors.DefaultFilePatterns {
		s, err := scannerFactory.CreateScanner(pattern.Ecosystem, a)
		if err != nil {
			return err
		}
		e.scanners[pattern.Ecosystem] = s
	}

	return nil
}
