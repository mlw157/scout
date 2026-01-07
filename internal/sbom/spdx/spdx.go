// SPDX SBOM Generator
// Based on SPDX Specification v2.3
// https://spdx.github.io/spdx-spec/v2.3/

package spdx

import (
	"crypto/sha256"
	"encoding/hex"
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

// creates a new SBOM generator
func NewGenerator(outputFile string) *Generator {
	return &Generator{OutputFile: outputFile}
}

// root SPDX document
type Document struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      CreationInfo   `json:"creationInfo"`
	Packages          []Package      `json:"packages,omitempty"`
	Relationships     []Relationship `json:"relationships,omitempty"`
	DocumentDescribes []string       `json:"documentDescribes,omitempty"`
}

// creation metadata
type CreationInfo struct {
	Created            string   `json:"created"`
	Creators           []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion,omitempty"`
}

// software package in SPDX info
type Package struct {
	SPDXID                string        `json:"SPDXID"`
	Name                  string        `json:"name"`
	VersionInfo           string        `json:"versionInfo,omitempty"`
	DownloadLocation      string        `json:"downloadLocation"`
	FilesAnalyzed         bool          `json:"filesAnalyzed"`
	LicenseConcluded      string        `json:"licenseConcluded,omitempty"`
	LicenseDeclared       string        `json:"licenseDeclared,omitempty"`
	CopyrightText         string        `json:"copyrightText,omitempty"`
	ExternalRefs          []ExternalRef `json:"externalRefs,omitempty"`
	PrimaryPackagePurpose string        `json:"primaryPackagePurpose,omitempty"`
}

// external reference for a package (PURL)
type ExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// relationship between SPDX elements
type Relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// creates an SBOM from scan results
func (g *Generator) Generate(results []*models.ScanResult) error {
	file, err := os.Create(g.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", g.OutputFile, err)
	}
	defer file.Close()

	// avoid duplicates
	packageMap := make(map[string]Package)
	var relationships []Relationship
	var documentDescribes []string

	// unique name for this document
	namespace := fmt.Sprintf("urn:uuid:%s", uuid.New().String())

	for _, result := range results {
		for _, dep := range result.Dependencies {
			spdxID := generateSPDXID(dep)
			if _, exists := packageMap[spdxID]; !exists {
				pkg := Package{
					SPDXID:                spdxID,
					Name:                  dep.Name,
					VersionInfo:           dep.Version,
					DownloadLocation:      "NOASSERTION",
					FilesAnalyzed:         false,
					LicenseConcluded:      "NOASSERTION",
					LicenseDeclared:       "NOASSERTION",
					CopyrightText:         "NOASSERTION",
					PrimaryPackagePurpose: "LIBRARY",
					ExternalRefs: []ExternalRef{
						{
							ReferenceCategory: "PACKAGE-MANAGER",
							ReferenceType:     "purl",
							ReferenceLocator:  generatePURL(dep),
						},
					},
				}
				packageMap[spdxID] = pkg
				documentDescribes = append(documentDescribes, spdxID)

				// Add relationship: DOCUMENT DESCRIBES PACKAGE
				relationships = append(relationships, Relationship{
					SPDXElementID:      "SPDXRef-DOCUMENT",
					RelationshipType:   "DESCRIBES",
					RelatedSPDXElement: spdxID,
				})
			}
		}
	}

	var packages []Package
	for _, pkg := range packageMap {
		packages = append(packages, pkg)
	}

	doc := Document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "scout",
		DocumentNamespace: namespace,
		CreationInfo: CreationInfo{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{"Tool: scout"},
		},
		Packages:          packages,
		Relationships:     relationships,
		DocumentDescribes: documentDescribes,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("failed to encode results to SPDX format: %v", err)
	}

	log.Printf("SBOM exported to %s in SPDX format\n", g.OutputFile)
	return nil
}

// creates a valid SPDX identifier for a package, must match: [a-zA-Z0-9.-]+
func generateSPDXID(dep models.Dependency) string {
	// ensure uniqueness and valid characters
	input := fmt.Sprintf("%s@%s", dep.Name, dep.Version)
	hash := sha256.Sum256([]byte(input))
	shortHash := hex.EncodeToString(hash[:8])

	safeName := sanitizeForSPDXID(dep.Name)

	return fmt.Sprintf("SPDXRef-Package-%s-%s", safeName, shortHash)
}

// removes or replaces characters not allowed in SPDX IDs
func sanitizeForSPDXID(name string) string {
	result := strings.ReplaceAll(name, "/", "-")
	result = strings.ReplaceAll(result, "@", "-")
	result = strings.ReplaceAll(result, ":", "-")
	result = strings.ReplaceAll(result, "_", "-")

	// Remove any remaining invalid characters
	var sanitized strings.Builder
	for _, r := range result {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			sanitized.WriteRune(r)
		}
	}

	// Ensure it doesn't start with a number
	s := sanitized.String()
	if len(s) > 0 && s[0] >= '0' && s[0] <= '9' {
		s = "pkg-" + s
	}

	if s == "" {
		return "unknown"
	}

	return s
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
