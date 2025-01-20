package factories

import (
	"errors"
	"github.com/mlw157/scout/internal/advisories"
	goparser "github.com/mlw157/scout/internal/parsers/go"
	mavenparser "github.com/mlw157/scout/internal/parsers/maven"
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
	default:
		return nil, errors.New("unsupported ecosystem: " + ecosystem)
	}
}
