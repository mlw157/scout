package factories

import (
	"errors"
	"github.com/mlw157/Scout/internal/advisories"
	goparser "github.com/mlw157/Scout/internal/parsers/go"
	"github.com/mlw157/Scout/internal/scanner"
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
	default:
		return nil, errors.New("unsupported ecosystem: " + ecosystem)
	}
}
