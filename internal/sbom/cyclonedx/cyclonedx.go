// CycloneDX SBOM Generator
// Based on CycloneDX Specification v1.5
// https://cyclonedx.org/specification/overview/

package cyclonedx

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mlw157/scout/internal/models"
)

type Generator struct {
	OutputFile string
}

func NewGenerator(outputFile string) *Generator {
	return &Generator{OutputFile: outputFile}
}

// root CycloneDX Bill of Materials
type BOM struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber,omitempty"`
	Version      int         `json:"version"`
	Metadata     *Metadata   `json:"metadata,omitempty"`
	Components   []Component `json:"components,omitempty"`
}

type Metadata struct {
	Timestamp string       `json:"timestamp,omitempty"`
	Tools     *ToolsChoice `json:"tools,omitempty"`
	Component *Component   `json:"component,omitempty"`
}

type ToolsChoice struct {
	Components []Component `json:"components,omitempty"`
}

// software component in the BOM
type Component struct {
	Type               string              `json:"type"`
	BOMRef             string              `json:"bom-ref,omitempty"`
	Name               string              `json:"name"`
	Version            string              `json:"version,omitempty"`
	PURL               string              `json:"purl,omitempty"`
	Licenses           []LicenseChoice     `json:"licenses,omitempty"`
	ExternalReferences []ExternalReference `json:"externalReferences,omitempty"`
}

// license information
type LicenseChoice struct {
	License *License `json:"license,omitempty"`
}

type License struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// reference to external resources (PURL)
type ExternalReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// creates an SBOM from scan results
func (g *Generator) Generate(results []*models.ScanResult) error {
	file, err := os.Create(g.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", g.OutputFile, err)
	}
	defer file.Close()

	// avoid duplicates
	componentMap := make(map[string]Component)

	for _, result := range results {
		for _, dep := range result.Dependencies {
			bomRef := generateBOMRef(dep)
			if _, exists := componentMap[bomRef]; !exists {
				componentMap[bomRef] = Component{
					Type:    "library",
					BOMRef:  bomRef,
					Name:    dep.Name,
					Version: dep.Version,
					PURL:    generatePURL(dep),
				}
			}
		}
	}

	var components []Component
	for _, comp := range componentMap {
		components = append(components, comp)
	}

	bom := BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:%s", uuid.New().String()),
		Version:      1,
		Metadata: &Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: &ToolsChoice{
				Components: []Component{
					{
						Type:    "application",
						Name:    "scout",
						Version: "0.1.0",
					},
				},
			},
		},
		Components: components,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(bom); err != nil {
		return fmt.Errorf("failed to encode results to CycloneDX format: %v", err)
	}

	log.Printf("SBOM exported to %s in CycloneDX format\n", g.OutputFile)
	return nil
}

// creates a unique reference for a component
func generateBOMRef(dep models.Dependency) string {
	return fmt.Sprintf("%s@%s", dep.Name, dep.Version)
}

// creates a Package URL for the dependency
func generatePURL(dep models.Dependency) string {
	ecosystem := strings.ToLower(dep.Ecosystem)
	name := dep.Name
	version := dep.Version

	switch ecosystem {
	case "go":
		return fmt.Sprintf("pkg:golang/%s@%s", name, version)
	case "npm":
		// Handle scoped packages
		if strings.HasPrefix(name, "@") {
			parts := strings.SplitN(name, "/", 2)
			if len(parts) == 2 {
				return fmt.Sprintf("pkg:npm/%s/%s@%s", parts[0][1:], parts[1], version)
			}
		}
		return fmt.Sprintf("pkg:npm/%s@%s", name, version)
	case "pip", "pypi":
		return fmt.Sprintf("pkg:pypi/%s@%s", name, version)
	case "maven":
		// Maven packages typically have group:artifact format
		if strings.Contains(name, ":") {
			parts := strings.SplitN(name, ":", 2)
			return fmt.Sprintf("pkg:maven/%s/%s@%s", parts[0], parts[1], version)
		}
		return fmt.Sprintf("pkg:maven/%s@%s", name, version)
	case "composer", "php":
		return fmt.Sprintf("pkg:composer/%s@%s", name, version)
	case "gem", "rubygems":
		return fmt.Sprintf("pkg:gem/%s@%s", name, version)
	case "crates.io", "cargo", "rust":
		return fmt.Sprintf("pkg:cargo/%s@%s", name, version)
	default:
		return fmt.Sprintf("pkg:generic/%s@%s", name, version)
	}
}
