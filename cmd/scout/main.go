package main

import (
	"flag"
	"github.com/mlw157/scout/internal/detectors/filesystem"
	"github.com/mlw157/scout/internal/engine"
	"github.com/mlw157/scout/internal/exporters/dojoexporter"
	"github.com/mlw157/scout/internal/exporters/htmlexporter"
	"github.com/mlw157/scout/internal/exporters/jsonexporter"
	"log"
	"strings"
)

func main() {

	art := `
   _____                  __ 
  / ___/_________  __  __/ /_
  \__ \/ ___/ __ \/ / / / __/
 ___/ / /__/ /_/ / /_/ / /_  
/____/\___/\____/\__,_/\__/

`
	originalFlags := log.Flags()
	log.SetFlags(0)

	log.Printf(art)

	log.SetFlags(originalFlags)

	ecosystemsFlag := flag.String("ecosystems", "", "Comma-separated list of ecosystems to scan (e.g., go,pip,maven)")
	excludeDirsFlag := flag.String("exclude", "", "Comma-separated list of directory and file names to exclude (e.g., node_modules,.git,requirements-dev.txt)")
	exportFormatFlag := flag.String("format", "json", "Export format: 'json' or 'dojo' (DefectDojo format)")
	outputFileFlag := flag.String("output", "", "Output file path (defaults to scout_report.[format])")
	tokenFlag := flag.String("token", "", "GitHub token for authenticated API requests (optional and deprecated)")
	sequentialFlag := flag.Bool("sequential", false, "Processes each file individually without concurrent execution (not recommended)")
	updateFlag := flag.Bool("update-db", false, "Download and use the latest version of scout database")

	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		log.Fatal("Please provide a root directory to scan")
	}

	rootDir := args[0]

	// ecosystems flag
	var ecosystems []string

	if *ecosystemsFlag != "" {
		ecosystems = strings.Split(*ecosystemsFlag, ",")
	} else {
		// default ecosystems
		ecosystems = []string{"go", "maven", "pip", "npm", "composer"}
	}

	// exclude directories flag
	var excludeDirs []string

	if *excludeDirsFlag != "" {
		excludeDirs = strings.Split(*excludeDirsFlag, ",")
	} else {
		excludeDirs = []string{}
	}

	log.Printf("Path to scan: %s\n", rootDir)
	log.Printf("Ecosystems to scan: %v\n", ecosystems)
	log.Printf("Excluded directories: %v\n", excludeDirs)

	detector := filesystem.NewFSDetector()

	config := engine.Config{
		Ecosystems:     ecosystems,
		ExcludeFiles:   excludeDirs,
		Token:          *tokenFlag,
		SequentialMode: *sequentialFlag,
		LatestMode:     *updateFlag,
	}

	// if export flag is set, create a exporter
	// todo make multiple export types, other than json and dojo
	outputFile := *outputFileFlag
	if outputFile == "" {
		if *exportFormatFlag == "dojo" {
			outputFile = "scout_report_dojo.json"
		} else if *exportFormatFlag == "html" {
			outputFile = "scout_report.html"
		} else {
			outputFile = "scout_report.json"
		}
	}

	switch *exportFormatFlag {
	case "dojo":
		config.Exporter = dojoexporter.NewDojoExporter(outputFile)
		log.Printf("Will export results in DefectDojo format to %s\n", outputFile)
	case "html":
		config.Exporter = htmlexporter.NewHTMLEXporter(outputFile)
		log.Printf("Will export results in HTML format to %s\n", outputFile)
	default:
		config.Exporter = jsonexporter.NewJSONExporter(outputFile)
		log.Printf("Will export results in JSON format to %s\n", outputFile)
	}

	scanEngine := engine.NewEngine(detector, config)

	scanResults, err := scanEngine.Scan(rootDir)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	log.Printf("Scan results for directory: %s\n\n", rootDir)

	totalVulnerabilities := 0
	totalPackages := 0

	for _, result := range scanResults {
		/*
			log.Println("File: " + result.SourceFile)
			log.Printf("Found %d vulnerabilities in %d packages\n\n", len(result.Vulnerabilities), len(result.Dependencies))

			if len(result.Vulnerabilities) > 0 {
				log.Println("Vulnerabilities found:")
				fmt.Println()
				for _, vulnerability := range result.Vulnerabilities {
					log.Printf("Package: %s@%s\n", vulnerability.Dependency.Name, vulnerability.Dependency.Version)
					log.Printf("CVE: %s\n", vulnerability.CVE)
					log.Printf("Severity: %s\n", vulnerability.Severity)
					log.Printf("Summary: %s\n", vulnerability.Summary)
					log.Printf("Upgrade to version %s in order to fix\n", vulnerability.FirstPatchedVersion)
					fmt.Println()

				}
			}
		*/
		totalPackages += len(result.Dependencies)
		totalVulnerabilities += len(result.Vulnerabilities)
	}
	log.Println("────────────────────────────────────────")
	log.Printf("Scan completed: %d vulnerabilities found in %d packages.\n", totalVulnerabilities, totalPackages)
	if totalVulnerabilities > 0 {
		log.Println("⚠️  Review the exported report for details.")
	} else {
		log.Println("✅ No vulnerabilities detected.")
	}
	log.Println("────────────────────────────────────────")

}
