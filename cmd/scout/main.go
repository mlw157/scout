package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/mlw157/scout/internal/detectors/filesystem"
	"github.com/mlw157/scout/internal/engine"
	"github.com/mlw157/scout/internal/exporters/dojoexporter"
	"github.com/mlw157/scout/internal/exporters/htmlexporter"
	"github.com/mlw157/scout/internal/exporters/jsonexporter"
	"github.com/mlw157/scout/internal/exporters/sarifexporter"
	"github.com/mlw157/scout/internal/sbom"
	"github.com/mlw157/scout/internal/sbom/cyclonedx"
	"github.com/mlw157/scout/internal/sbom/spdx"
)

// version is injected at build time via ldflags
var version = "dev"

const art = `
   _____                  __ 
  / ___/_________  __  __/ /_
  \__ \/ ___/ __ \/ / / / __/
 ___/ / /__/ /_/ / /_/ / /_  
/____/\___/\____/\__,_/\__/
`

func main() {
	// Define flags with both long and short versions
	var (
		ecosystemsFlag   string
		excludeDirsFlag  string
		exportFormatFlag string
		outputFileFlag   string
		tokenFlag        string
		sequentialFlag   bool
		updateFlag       bool
		versionFlag      bool
		helpFlag         bool
		sbomFlag         string
		sbomOnlyFlag     string
		sbomOutputFlag   string
	)

	// Long flags
	flag.StringVar(&ecosystemsFlag, "ecosystems", "", "Comma-separated list of ecosystems to scan (e.g., go,pip,maven)")
	flag.StringVar(&excludeDirsFlag, "exclude", "", "Comma-separated list of directory and file names to exclude")
	flag.StringVar(&exportFormatFlag, "format", "json", "Export format: json, html, sarif, or dojo (DefectDojo)")
	flag.StringVar(&outputFileFlag, "output", "", "Output file path (defaults to scout_report.[format])")
	flag.StringVar(&tokenFlag, "token", "", "GitHub token for authenticated API requests (deprecated)")
	flag.BoolVar(&sequentialFlag, "sequential", false, "Process files sequentially instead of concurrently")
	flag.BoolVar(&updateFlag, "update-db", false, "Download and use the latest version of scout database")
	flag.BoolVar(&versionFlag, "version", false, "Print version and exit")
	flag.BoolVar(&helpFlag, "help", false, "Show help message")
	flag.StringVar(&sbomFlag, "sbom", "", "Generate SBOM (cyclonedx, spdx) along with vulnerability scan")
	flag.StringVar(&sbomOnlyFlag, "sbom-only", "", "Generate SBOM only, skip vulnerability scan (cyclonedx, spdx)")
	flag.StringVar(&sbomOutputFlag, "sbom-output", "", "Output file for SBOM (defaults to sbom.[format].json)")

	// Short flag aliases
	flag.StringVar(&ecosystemsFlag, "e", "", "Alias for --ecosystems")
	flag.StringVar(&excludeDirsFlag, "x", "", "Alias for --exclude")
	flag.StringVar(&exportFormatFlag, "f", "json", "Alias for --format")
	flag.StringVar(&outputFileFlag, "o", "", "Alias for --output")
	flag.BoolVar(&versionFlag, "v", false, "Alias for --version")
	flag.BoolVar(&helpFlag, "h", false, "Alias for --help")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, art)
		fmt.Fprintln(os.Stderr, "Scout - Dependency Vulnerability Scanner")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  scout [options] <directory>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  scout .                              # Scan current directory")
		fmt.Fprintln(os.Stderr, "  scout --ecosystems go,npm ./app      # Scan specific ecosystems")
		fmt.Fprintln(os.Stderr, "  scout --format html -o report.html . # Export as HTML")
		fmt.Fprintln(os.Stderr, "  scout --sbom cyclonedx .             # Vuln scan + SBOM generation")
		fmt.Fprintln(os.Stderr, "  scout --sbom-only cyclonedx .        # SBOM only (no vuln scan)")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
	}

	flag.Parse()

	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	if versionFlag {
		fmt.Printf("scout v%s\n", version)
		os.Exit(0)
	}

	fmt.Print(art)

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Error: missing required argument <directory>")
		fmt.Fprintln(os.Stderr)
		flag.Usage()
		os.Exit(1)
	}

	rootDir := args[0]

	// Validate directory exists
	info, err := os.Stat(rootDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot access path: %s\n", err)
		os.Exit(1)
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Path is not a directory: %s\n", rootDir)
		os.Exit(1)
	}

	// Warn about deprecated token flag
	if tokenFlag != "" {
		fmt.Println("⚠️  Warning: --token flag is deprecated and will be removed in a future version")
	}

	// Determine SBOM format and mode
	// --sbom-only takes precedence (SBOM only, no scan)
	// --sbom means SBOM + scan
	sbomFormat := ""
	skipVulnScan := false

	if sbomOnlyFlag != "" {
		sbomFormat = sbomOnlyFlag
		skipVulnScan = true
	} else if sbomFlag != "" {
		sbomFormat = sbomFlag
		skipVulnScan = false
	}

	// Validate SBOM format if specified
	if sbomFormat != "" {
		validSBOMFormats := map[string]bool{"cyclonedx": true, "spdx": true}
		if !validSBOMFormats[sbomFormat] {
			fmt.Fprintf(os.Stderr, "Invalid SBOM format '%s'. Valid options: cyclonedx, spdx\n", sbomFormat)
			os.Exit(1)
		}
	}

	// Warn if both --sbom and --sbom-only are provided
	if sbomFlag != "" && sbomOnlyFlag != "" {
		fmt.Println("Note: --sbom-only takes precedence, skipping vulnerability scan")
	}

	// Parse ecosystems and normalize to canonical names
	ecosystemAliases := map[string]string{
		"ruby": "gem",
		"rust": "crates.io",
		"go":   "Go",
	}
	var ecosystems []string
	if ecosystemsFlag != "" {
		for _, eco := range strings.Split(ecosystemsFlag, ",") {
			eco = strings.TrimSpace(eco)
			if canonical, ok := ecosystemAliases[eco]; ok {
				eco = canonical
			}
			ecosystems = append(ecosystems, eco)
		}
	} else {
		ecosystems = []string{"Go", "maven", "pip", "npm", "composer", "gem", "crates.io"}
	}

	// Parse exclude directories
	var excludeDirs []string
	if excludeDirsFlag != "" {
		excludeDirs = strings.Split(excludeDirsFlag, ",")
	}

	// Validate export format
	validFormats := map[string]bool{"json": true, "dojo": true, "html": true, "sarif": true}
	if !validFormats[exportFormatFlag] {
		fmt.Fprintf(os.Stderr, "Invalid format '%s'. Valid options: json, html, sarif, dojo\n", exportFormatFlag)
		os.Exit(1)
	}

	fmt.Println("Path:", rootDir)
	fmt.Println("Ecosystems:", ecosystems)
	if len(excludeDirs) > 0 {
		fmt.Println("Excluded:", excludeDirs)
	}

	detector := filesystem.NewFSDetector()
	sbomGenerated := false
	scanPerformed := false
	hasVulnerabilities := false

	// Generate SBOM if requested
	if sbomFormat != "" {
		sbomOutput := sbomOutputFlag
		if sbomOutput == "" {
			switch sbomFormat {
			case "cyclonedx":
				sbomOutput = "sbom.cdx.json"
			case "spdx":
				sbomOutput = "sbom.spdx.json"
			}
		}

		fmt.Println()
		fmt.Println("Generating SBOM...")
		fmt.Printf("   Format: %s\n", sbomFormat)
		fmt.Printf("   Output: %s\n", sbomOutput)

		var generator sbom.Generator
		switch sbomFormat {
		case "cyclonedx":
			generator = cyclonedx.NewGenerator(sbomOutput)
		case "spdx":
			generator = spdx.NewGenerator(sbomOutput)
		}

		sbomConfig := sbom.Config{
			Detector:     detector,
			Ecosystems:   ecosystems,
			ExcludeFiles: excludeDirs,
			OutputFile:   sbomOutput,
		}

		sbomService := sbom.NewService(sbomConfig, generator)
		if err := sbomService.Generate(rootDir); err != nil {
			fmt.Fprintf(os.Stderr, "SBOM generation failed: %v\n", err)
			os.Exit(1)
		}
		sbomGenerated = true
	}

	// Run vulnerability scan unless --sbom-only is set
	if !skipVulnScan {
		// Validate export format
		validFormats := map[string]bool{"json": true, "dojo": true, "html": true, "sarif": true}
		if !validFormats[exportFormatFlag] {
			fmt.Fprintf(os.Stderr, "Invalid format '%s'. Valid options: json, html, sarif, dojo\n", exportFormatFlag)
			os.Exit(1)
		}

		config := engine.Config{
			Ecosystems:     ecosystems,
			ExcludeFiles:   excludeDirs,
			Token:          tokenFlag,
			SequentialMode: sequentialFlag,
			LatestMode:     updateFlag,
		}

		formatExtensions := map[string]string{
			"json":  ".json",
			"dojo":  ".json",
			"html":  ".html",
			"sarif": ".sarif",
		}
		ext := formatExtensions[exportFormatFlag]

		outputFile := outputFileFlag
		if outputFile == "" {
			switch exportFormatFlag {
			case "dojo":
				outputFile = "scout_report_dojo.json"
			case "html":
				outputFile = "scout_report.html"
			case "sarif":
				outputFile = "scout_report.sarif"
			default:
				outputFile = "scout_report.json"
			}
		} else if !strings.HasSuffix(outputFile, ext) {
			outputFile += ext
		}

		switch exportFormatFlag {
		case "dojo":
			config.Exporter = dojoexporter.NewDojoExporter(outputFile)
		case "html":
			config.Exporter = htmlexporter.NewHTMLEXporter(outputFile)
		case "sarif":
			config.Exporter = sarifexporter.NewSARIFExporter(outputFile)
		default:
			config.Exporter = jsonexporter.NewJSONExporter(outputFile)
		}

		fmt.Println()
		fmt.Println("🔍 Scanning for vulnerabilities...")
		fmt.Printf("   Format: %s\n", exportFormatFlag)
		fmt.Printf("   Output: %s\n", outputFile)

		scanEngine := engine.NewEngine(detector, config)

		scanResults, err := scanEngine.Scan(rootDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
			os.Exit(1)
		}

		scanPerformed = true

		totalVulnerabilities := 0
		totalPackages := 0

		for _, result := range scanResults {
			totalPackages += len(result.Dependencies)
			totalVulnerabilities += len(result.Vulnerabilities)
		}

		fmt.Printf("\n   Found %d vulnerabilities in %d packages.\n", totalVulnerabilities, totalPackages)
		hasVulnerabilities = totalVulnerabilities > 0
	}

	// Print summary
	fmt.Println()
	fmt.Println("────────────────────────────────────────")

	if sbomGenerated {
		fmt.Println("✅ SBOM generated successfully.")
	}

	if scanPerformed {
		if hasVulnerabilities {
			fmt.Println("⚠️  Vulnerabilities detected. Review the report for details.")
		} else {
			fmt.Println("✅ No vulnerabilities detected.")
		}
	}

	fmt.Println("────────────────────────────────────────")

	if hasVulnerabilities {
		os.Exit(1)
	}
}
