package main

import (
	"fmt"
	"github.com/mlw157/GoScan/internal/advisories"
	"github.com/mlw157/GoScan/internal/models"
	goparser "github.com/mlw157/GoScan/internal/parsers/go"
	"log"
	"os"
)

// todo this is a simple test main file (REDO!!!!)
func fetchVulnerabilities(goModFilePath string) ([]models.Vulnerability, error) {
	fileData, err := goparser.ReadFile(goModFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read go.mod file: %v", err)
	}

	dependencies, err := goparser.ParseFile(fileData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod file: %v", err)
	}

	advisor := advisories.NewGitHubAdvisoryService()

	vulnerabilities, err := advisor.FetchVulnerabilities(dependencies)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch vulnerabilities: %v", err)
	}

	return vulnerabilities, nil
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go <path-to-go.mod>")
	}

	goModFilePath := os.Args[1]

	vulnerabilities, err := fetchVulnerabilities(goModFilePath)
	if err != nil {
		log.Fatalf("Error fetching vulnerabilities: %v", err)
	}

	if len(vulnerabilities) == 0 {
		fmt.Println("No vulnerabilities found.")
		return
	}

	fmt.Println("Vulnerabilities found:")
	for _, vulnerability := range vulnerabilities {
		fmt.Printf("Dependency: %s\n", vulnerability.Dependency.Name)
		fmt.Printf("CVE: %s\n", vulnerability.CVE)
		fmt.Printf("Description: %s\n", vulnerability.Description)
		fmt.Printf("Severity: %s\n", vulnerability.Severity)
		fmt.Printf("Affected Versions: %s\n", vulnerability.AffectedVersions)
		fmt.Println("===================================")
	}
}
