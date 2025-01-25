package factories

import (
	"errors"
	"github.com/mlw157/scout/internal/advisories"
	goparser "github.com/mlw157/scout/internal/parsers/go"
	mavenparser "github.com/mlw157/scout/internal/parsers/java"
	npmparser "github.com/mlw157/scout/internal/parsers/npm"
	composerparser "github.com/mlw157/scout/internal/parsers/php"
	pythonparser "github.com/mlw157/scout/internal/parsers/python"
	"github.com/mlw157/scout/internal/scanner"
)

type ScannerFactory struct {
}

func NewScannerFactory() *ScannerFactory {
	return &ScannerFactory{}
}

func (f *ScannerFactory) CreateScanner(ecosystem string, advisory advisories.AdvisoryService) (*scanner.Scanner, error) {
	switch ecosystem {
	case "go":
		return scanner.NewScanner(goparser.NewGoParser(), advisory), nil
	case "maven":
		return scanner.NewScanner(mavenparser.NewMavenParser(), advisory), nil
	case "pip":
		return scanner.NewScanner(pythonparser.NewPipParser(), advisory), nil
	case "npm":
		return scanner.NewScanner(npmparser.NewNodeParser(), advisory), nil
	case "composer":
		return scanner.NewScanner(composerparser.NewComposerParser(), advisory), nil

	default:
		return nil, errors.New("unsupported ecosystem: " + ecosystem)
	}
}
