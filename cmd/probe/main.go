package main

import (
	"fmt"
	"github.com/mlw157/Probe/internal/advisories/gh"
	goparser "github.com/mlw157/Probe/internal/parsers/go"
	"github.com/mlw157/Probe/internal/scanner"
	"log"
	"os"
)

// just to test
func main() {
	if len(os.Args) < 2 {
		log.Fatal("Please provide a file to scan.")
	}

	pathToScan := os.Args[1]

	goParser := goparser.NewGoParser()
	githubAdvisory := gh.NewGitHubAdvisoryService()

	goScanner := scanner.NewScanner(goParser, githubAdvisory)

	fmt.Print("Scanning\n\n")
	result, err := goScanner.ScanFile(pathToScan)

	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	fmt.Printf("Scan results for: %s\n\n", pathToScan)
	fmt.Printf("Found %d vulnerabilities in %d packages\n\n", len(result.Vulnerabilities), len(result.Dependencies))

	if len(result.Vulnerabilities) > 0 {
		fmt.Println("Vulnerabilities found:")
		fmt.Println()

		for _, vuln := range result.Vulnerabilities {
			fmt.Printf("Package: %s@%s\n", vuln.Dependency.Name, vuln.Dependency.Version)
			fmt.Printf("CVE: %s\n", vuln.CVE)
			fmt.Printf("Severity: %s\n", vuln.Severity)
			fmt.Printf("Summary: %s\n", vuln.Summary)
			fmt.Printf("Upgrade to version %s in order to fix\n", vuln.FirstPatchedVersion)
			fmt.Println()

		}
	}

}
