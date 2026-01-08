package sbom

import (
	"fmt"
	"log"

	"github.com/mlw157/scout/internal/detectors"
	"github.com/mlw157/scout/internal/models"
	"github.com/mlw157/scout/internal/parsers"
	goparser "github.com/mlw157/scout/internal/parsers/go"
	mavenparser "github.com/mlw157/scout/internal/parsers/java"
	npmparser "github.com/mlw157/scout/internal/parsers/npm"
	composerparser "github.com/mlw157/scout/internal/parsers/php"
	pythonparser "github.com/mlw157/scout/internal/parsers/python"
	rubyparser "github.com/mlw157/scout/internal/parsers/ruby"
	rustparser "github.com/mlw157/scout/internal/parsers/rust"
)

type Generator interface {
	Generate(results []*models.ScanResult) error
}

type Config struct {
	Detector     detectors.Detector
	Ecosystems   []string
	ExcludeFiles []string
	OutputFile   string
}

// Service - SBOM generation without vulnerability scanning
type Service struct {
	config    Config
	generator Generator
	parsers   map[string]parsers.Parser
}

// NewService creates a new SBOM generation service
func NewService(config Config, generator Generator) *Service {
	return &Service{
		config:    config,
		generator: generator,
		parsers:   make(map[string]parsers.Parser),
	}
}

func (s *Service) Generate(root string) error {
	// Initialize parsers for requested ecosystems
	if err := s.populateParsers(); err != nil {
		return fmt.Errorf("failed to initialize parsers: %w", err)
	}

	// Detect dependency files
	files, err := s.config.Detector.DetectFiles(root, s.config.ExcludeFiles, s.config.Ecosystems)
	if err != nil {
		return fmt.Errorf("failed to detect files: %w", err)
	}

	// Parse each file to extract dependencies
	var results []*models.ScanResult
	for _, file := range files {
		parser, exists := s.parsers[file.Ecosystem]
		if !exists {
			log.Printf("No parser for ecosystem %s, skipping %s\n", file.Ecosystem, file.Path)
			continue
		}

		log.Printf("Parsing %s for SBOM\n", file.Path)
		deps, err := parser.ParseFile(file.Path)
		if err != nil {
			log.Printf("Failed to parse %s: %v\n", file.Path, err)
			continue
		}

		results = append(results, &models.ScanResult{
			Dependencies: deps,
			SourceFile:   file.Path,
		})
	}

	if err := s.generator.Generate(results); err != nil {
		return fmt.Errorf("failed to generate SBOM: %w", err)
	}

	return nil
}

func (s *Service) populateParsers() error {
	ecosystems := s.config.Ecosystems
	if len(ecosystems) == 0 {
		ecosystems = []string{"Go", "maven", "pip", "npm", "composer", "gem", "crates.io"}
	}

	for _, ecosystem := range ecosystems {
		if _, exists := s.parsers[ecosystem]; exists {
			continue
		}

		parser, err := createParser(ecosystem)
		if err != nil {
			return err
		}
		s.parsers[ecosystem] = parser
	}

	return nil
}

func createParser(ecosystem string) (parsers.Parser, error) {
	switch ecosystem {
	case "gem":
		return rubyparser.NewRubyParser(), nil
	case "crates.io":
		return rustparser.NewRustParser(), nil
	case "Go":
		return goparser.NewGoParser(), nil
	case "maven":
		return mavenparser.NewMavenParser(), nil
	case "pip":
		return pythonparser.NewPipParser(), nil
	case "npm":
		return npmparser.NewNodeParser(), nil
	case "composer":
		return composerparser.NewComposerParser(), nil
	default:
		return nil, fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}
}
