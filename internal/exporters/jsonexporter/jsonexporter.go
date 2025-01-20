package jsonexporter

import (
	"encoding/json"
	"fmt"
	"github.com/mlw157/Probe/internal/models"
	"os"
)

type JSONExporter struct {
	OutputFile string
}

func NewJSONExporter(outputFile string) *JSONExporter {
	return &JSONExporter{OutputFile: outputFile}
}

func (j *JSONExporter) Export(results []*models.ScanResult) error {
	// Create the output file
	file, err := os.Create(j.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", j.OutputFile, err)
	}
	defer file.Close()

	// counters
	totalPackages := 0
	totalVulnerabilities := 0
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	// Loop through scan results to count vulnerabilities and their severities
	for _, result := range results {
		totalPackages += len(result.Dependencies)
		totalVulnerabilities += len(result.Vulnerabilities)

		for _, vulnerability := range result.Vulnerabilities {
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
		"Total Packages":        totalPackages,
		"Total Vulnerabilities": totalVulnerabilities,
		"Critical":              criticalCount,
		"High":                  highCount,
		"Medium":                mediumCount,
		"Low":                   lowCount,
	}

	output := map[string]interface{}{
		"summary": summary,
		"results": results,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Pretty-print JSON
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("failed to encode results to JSON: %v", err)
	}

	fmt.Printf("Results exported to %s\n", j.OutputFile)
	return nil
}
