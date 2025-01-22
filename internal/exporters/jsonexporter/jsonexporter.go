package jsonexporter

import (
	"encoding/json"
	"fmt"
	"github.com/mlw157/scout/internal/models"
	"os"
)

type JSONExporter struct {
	OutputFile string
}

func NewJSONExporter(outputFile string) *JSONExporter {
	return &JSONExporter{OutputFile: outputFile}
}

func (j *JSONExporter) Export(results []*models.ScanResult) error {
	file, err := os.Create(j.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", j.OutputFile, err)
	}
	defer file.Close()

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	var vulnerabilities []map[string]interface{}

	// loop through scan results to count vulnerabilities and their severities
	for _, result := range results {
		for _, vulnerability := range result.Vulnerabilities {
			vulnWithFile := map[string]interface{}{
				"vulnerability": vulnerability,
				"file":          result.SourceFile,
			}

			vulnerabilities = append(vulnerabilities, vulnWithFile)

			switch vulnerability.Severity {
			case "critical":
				criticalCount++
			case "high":
				highCount++
			case "medium":
				mediumCount++
			case "low":
				lowCount++
			}
		}
	}

	summary := map[string]int{
		"Total Vulnerabilities": len(vulnerabilities),
		"Critical":              criticalCount,
		"High":                  highCount,
		"Medium":                mediumCount,
		"Low":                   lowCount,
	}

	output := map[string]interface{}{
		"summary":         summary,
		"vulnerabilities": vulnerabilities,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // pretty-print JSON
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("failed to encode results to JSON: %v", err)
	}

	fmt.Printf("Vulnerabilities exported to %s\n", j.OutputFile)
	return nil
}
