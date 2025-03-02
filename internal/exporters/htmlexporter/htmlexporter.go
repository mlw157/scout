package htmlexporter

import (
	"fmt"
	"github.com/mlw157/scout/internal/models"
	"html/template"
	"log"
	"os"
	"strings"
)

type HTMLEXporter struct {
	OutputFile string
}

func NewHTMLEXporter(outputFile string) *HTMLEXporter {
	return &HTMLEXporter{OutputFile: outputFile}
}

func (h *HTMLEXporter) Export(results []*models.ScanResult) error {
	file, err := os.Create(h.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", h.OutputFile, err)
	}
	defer file.Close()

	// Prepare the data for the HTML template
	var reportData []map[string]interface{}

	for _, result := range results {
		for _, vulnerability := range result.Vulnerabilities {
			// Map severity to custom HTML class
			severity := mapSeverity(strings.ToLower(vulnerability.Severity))

			// Create a simple report entry
			reportData = append(reportData, map[string]interface{}{
				"DependencyName":      template.HTMLEscapeString(vulnerability.Dependency.Name),
				"DependencyVersion":   template.HTMLEscapeString(vulnerability.Dependency.Version),
				"Severity":            severity,
				"CVE":                 template.HTMLEscapeString(vulnerability.CVE),
				"FirstPatchedVersion": template.HTMLEscapeString(vulnerability.FirstPatchedVersion),
				"AffectedFile":        template.HTMLEscapeString(result.SourceFile),
			})
		}
	}

	// Define the simplified HTML template
	const htmlTemplate = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Scout Report</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 20px;
                background-color: #f8f9fa;
            }
            
            table {
                width: 100%;
                border-collapse: collapse;
                background-color: white;
                border-radius: 5px;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            }
            
            th, td {
                padding: 12px 15px;
                text-align: left;
            }
            
            th {
                background-color: #343a40;
                color: white;
                font-weight: 500;
                text-transform: uppercase;
                font-size: 12px;
            }
            
            tr:nth-child(even) {
                background-color: #f8f9fa;
            }
            
            tr:hover {
                background-color: #e9ecef;
            }
            
            .severity-badge {
                display: inline-block;
                padding: 4px 8px;
                border-radius: 4px;
                font-weight: bold;
                text-transform: uppercase;
                font-size: 11px;
                color: white;
            }
            
            .Critical {
                background-color: #dc3545;
            }
            
            .High {
                background-color: #fd7e14;
            }
            
            .Medium {
                background-color: #ffc107;
                color: #212529;
            }
            
            .Low {
                background-color: #20c997;
            }
            
            .cve {
                font-family: monospace;
                padding: 2px 4px;
                background-color: #f1f3f5;
                border-radius: 3px;
            }
        </style>
    </head>
    <body>
        <h1>Scout Report</h1>
        <table>
            <thead>
                <tr>
                    <th style="width: 25%">Dependency</th>
                    <th style="width: 15%">Severity</th>
                    <th style="width: 20%">CVE</th>
                    <th style="width: 20%">First Patched Version</th>
                    <th style="width: 20%">Affected File</th>
                </tr>
            </thead>
            <tbody>
                {{range .}}
                <tr>
                    <td><strong>{{.DependencyName}}@{{.DependencyVersion}}</strong></td>
                    <td><span class="severity-badge {{.Severity}}">{{.Severity}}</span></td>
                    <td class="cve">{{if .CVE}}{{.CVE}}{{else}}-{{end}}</td>
                    <td>{{if .FirstPatchedVersion}}{{.FirstPatchedVersion}}{{else}}-{{end}}</td>
                    <td>{{.AffectedFile}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </body>
    </html>`

	// Create a template
	t, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %v", err)
	}

	if err := t.Execute(file, reportData); err != nil {
		return fmt.Errorf("failed to execute HTML template: %v", err)
	}

	log.Printf("Vulnerabilities exported to %s in HTML format\n", h.OutputFile)
	return nil
}

// mapSeverity maps Scout severity levels to custom HTML classes
func mapSeverity(scoutSeverity string) string {
	switch scoutSeverity {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "moderate":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Low" // default to Low if unknown
	}
}
