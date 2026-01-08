# Scout

Scout is a lightweight Software Composition Analysis (SCA) tool. It analyzes your project's dependencies and checks them against known vulnerabilities.

## Ecosystems Supported so far

**Go**: Scans go.mod files for vulnerabilities in Go dependencies.

**Maven**: Scans pom.xml files for vulnerabilities in Maven dependencies.

**Python**: Scans requirements.txt and poetry.lock files for vulnerabilities in pip dependencies.

**NPM**: Scans package.json, package-lock.json and yarn.lock files for vulnerabilities in npm dependencies.

**Composer**: Scans composer.json and composer.lock files for vulnerabilities in composer dependencies.

**Ruby**: Scans Gemfile.lock files for vulnerabilities in gem dependencies.

**Rust**: Scans Cargo.lock files for vulnerabilities in crates.io dependencies.

## Installation

**Supported platforms:** Linux and macOS. Windows users should use Docker.

### Docker

```bash
docker pull ghcr.io/mlw157/scout:latest && docker tag ghcr.io/mlw157/scout:latest scout:latest
```

### Binary releases

```bash
Download and unpack from https://github.com/mlw157/scout/releases
```

## Usage

Once you've downloaded the precompiled binary or built the image, you can run Scout directly from the command line.

### Database Storage

Scout stores its database in the ~/.cache/scout/db directory by default. If the database is not found or is missing, Scout will automatically download the required database files.
You can manually update the database using the `--update-db` flag if needed.

### Command-Line Flags

| Flag | Short | Description | Default | Example |
| --- | --- | --- | --- | --- |
| `--ecosystems` | `-e` | Ecosystems to scan | `all supported` | `-e maven,pip` |
| `--exclude` | `-x` | File/Directory patterns to exclude | - | `-x node_modules,.git` |
| `--format` | `-f` | Export format (json, html, sarif, dojo) | `json` | `-f html` |
| `--output` | `-o` | Output file path (extension auto-added) | `scout_report.[ext]` | `-o results` |
| `--sbom` | | Generate SBOM + run vulnerability scan (cyclonedx, spdx) | - | `--sbom cyclonedx` |
| `--sbom-only` | | Generate SBOM only, skip vulnerability scan (cyclonedx, spdx) | - | `--sbom-only spdx` |
| `--sbom-output` | | SBOM output file path | `sbom.[format].json` | `--sbom-output my-sbom.json` |
| `--update-db` | | Fetch the latest Scout database | `false` | `--update-db` |
| `--reviewed` | | Use reviewed database (manually verified vulnerabilities only) | `false` | `--reviewed` |
| `--version` | `-v` | Print version and exit | | `-v` |
| `--help` | `-h` | Show help message | | `-h` |

### Examples

```bash
# Scan current directory
scout .

# Scan for specific ecosystems only
scout -e maven,pip .

# Fetch the latest Scout database
scout --update-db .

# Export results to HTML format
scout -f html .

# Export with custom filename (extension auto-added based on format)
scout -f html -o my_report .

# Exclude directories or files
scout -x node_modules,testfolder .

# Generate SBOM only (no vulnerability scan)
scout --sbom-only cyclonedx .

# Generate SBOM in SPDX format (no vulnerability scan)
scout --sbom-only spdx .

# Run vulnerability scan AND generate SBOM
scout --sbom cyclonedx .

# SBOM with custom output filename
scout --sbom-only spdx --sbom-output my-project-sbom.json .
```

Running via Docker:

```bash
docker run --rm -v "${PWD}:/scan" scout:latest [flags] .
```

### GitHub Actions Example

Run Scout:

```yaml
name: "Scout"
on:
  workflow_dispatch:
jobs:
  scout:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
      - name: Get Scout
        run: |
          curl -LO "https://github.com/mlw157/scout/releases/download/v0.1.2/scout-linux-amd64.tar.gz"
          tar xvzf scout-linux-amd64.tar.gz
          rm scout-linux-amd64.tar.gz
          
      - name: Run Scout
        run: ./scout -exclude node_modules .
```

Send results to DefectDojo:

```yaml
name: "Scout to Dojo"
on:
  workflow_dispatch:
jobs:
  scout:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
      - name: Get Scout
        run: |
          curl -LO "https://github.com/mlw157/scout/releases/download/v0.1.2/scout-linux-amd64.tar.gz"
          tar xvzf scout-linux-amd64.tar.gz
          rm scout-linux-amd64.tar.gz
          
      - name: Run Scout
        run: ./scout -exclude node_modules -format dojo -output dojo.json .
      - name: Send to Dojo
        run: |
            curl -X POST 'https://your-dojo-endpoint.com/api/v2/import-scan/' \
              -H 'accept: application/json' \
              -H 'Authorization: Token ${{ secrets.DOJO_TOKEN }}' \
              -H 'Content-Type: multipart/form-data' \
              -F 'minimum_severity=Info' \
              -F 'active=true' \
              -F 'verified=false' \
              -F 'scan_type=Generic Findings Import' \
              -F 'file=@dojo.json;type=application/json' \
              -F 'engagement=1' \
              -F 'close_old_findings=true' \
              -F 'push_to_jira=false'
```

## Architecture

Scout is built using a modular, dependency injection-based architecture that allows for easy extension and customization:

### Core Components

- **Engine**: The main orchestrator that combines all components and runs the scanning process. It coordinates detectors, scanners, and exporters together.
  
- **Scanner**: Combines a parser and an advisory service to scan dependencies and identify vulnerabilities.

### Interfaces

- **Parser**: Parsers are responsible for analyzing dependency files and extracting dependencies. (e.g GoParser, MavenParser, NpmParser)
- **Advisory**: Advisories are services that analyze dependencies to identify vulnerabilities. (e.g GitHub Advisory Database, Snyk Vulnerability Database, NIST Vulnerability Database)
- **Detector**: Detectors are responsible for finding dependency files to scan. (e.g Filesystem Detector, GitRepositoryDetector)
- **Exporter**: Exporters take the scan results and present them in the desired format. (e.g JSONExporter, HTMLExporter, SARIFExporter)
- **SBOM Generator**: Generators create Software Bill of Materials in standard formats. (e.g CycloneDX, SPDX)

> **Note**: Some examples listed above are theoretical and not yet implemented. They are provided to illustrate potential future extensions of the system.

## SBOM Generation

Scout can generate Software Bill of Materials (SBOM) in industry-standard formats:

### Supported Formats

| Format | Spec Version | Output File | Use Case |
| --- | --- | --- | --- |
| **CycloneDX** | 1.5 | `sbom.cdx.json` | Security-focused, lightweight |
| **SPDX** | 2.3 | `sbom.spdx.json` | License compliance, ISO standard |

### SBOM Examples

```bash
# Generate CycloneDX SBOM (no vulnerability scan)
scout --sbom-only cyclonedx .

# Generate SPDX SBOM (no vulnerability scan)
scout --sbom-only spdx .

# Vulnerability scan + SBOM generation in one run
scout --sbom cyclonedx .

# SBOM for specific ecosystems only
scout --sbom-only spdx -e go,npm .
```

### SBOM Output

The generated SBOM includes:

- All detected dependencies with name and version
- Package URLs (PURL) for each dependency
- Metadata (timestamp, tool info, document identifiers)

## Next Features

- Support for more ecosystems
- Validation of transitive dependencies (dependencies of dependencies)
- Reachability analysis
