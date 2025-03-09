# Scout

Scout is a lightweight Software Composition Analysis (SCA) tool. It analyzes your project's dependencies and checks them against known vulnerabilities.
## Ecosystems Supported so far

**Go**: Scans go.mod files for vulnerabilities in Go dependencies.<br/>
**Maven**: Scans pom.xml files for vulnerabilities in Maven dependencies.<br/>
**Python**: Scans requirements.txt files for vulnerabilities in pip dependencies.<br/>
**NPM**: Scans package.json, package-lock.json and yarn.lock files for vulnerabilities in npm dependencies.<br/>
**Composer**: Scans composer.json and composer.lock files for vulnerabilities in composer dependencies.<br/>

## Installation
### Docker

```bash
docker pull ghcr.io/mlw157/scout:latest && docker tag ghcr.io/mlw157/scout:latest scout:latest
```
### Binary releases
```bash
Download and unpack from https://github.com/mlw157/scout/releases
```
## Usage
Once you’ve downloaded the precompiled binary or built the image, you can run Scout directly from the command line.
### Database Storage
Scout stores its database in the ~/.cache/scout/db directory by default. If the database is not found or is missing, Scout will automatically download the required database files. <br/>
You can manually update the database using the ```-update-db``` flag if needed.
### Command-Line Flags

| Flag | Description | Default | Example |
| --- | --- | --- | --- |
| `-ecosystems` | Ecosystems to scan | `all supported ones` | `-ecosystems maven,pip` |
| `-exclude` | File/Directory patterns to exclude | - | `-exclude node_modules,.git` |
| `-format` | Export format (options: dojo, html, json) | `json` | `-format dojo` |
| `-output` | Output file path | `[format]` | `-output custom_report.json` |
| `-update-db` | Fetch the latest Scout database| `false` | `-update-db` |

### Example
Default
```bash
scout .
```
Scan current directory for only maven dependencies
```bash
scout -ecosystems maven .
```
Fetch the latest Scout database
```bash
scout -update-db .
```
Export results to defect dojo format
```bash
scout -format dojo .
```
Export results with a custom report name
```bash
scout -format html -output custom_name.html .
```
Exclude subdirectories or files
```bash
scout -exclude node_modules,testfolder .
```
**Running via Docker**
```bash
docker run --rm -v "${PWD}:/scan" scout:latest [flags] .
```

  > **Note**: When importing to results to DefectDojo, use Generic Findings Import scan type.

## Architecture
Scout is built using a modular, dependency injection-based architecture that allows for easy extension and customization:

### Core Components
- **Engine**: The main orchestrator that combines all components and runs the scanning process. It coordinates detectors, scanners, and exporters together.
- **Scanner**: Combines a parser and an advisory service to scan dependencies and identify vulnerabilities.

### Interfaces

- **Parser**: Parsers are responsible for analyzing dependency files and extracting dependencies. (e.g GoParser, MavenParser, NpmParser)
  
- **Advisory**: Advisories are services that analyze dependencies to identify vulnerabilities. (e.g GitHub Advisory Database, Snyk Vulnerability Database, NIST Vulnerability Database)

- **Detector**: Detectors are responsible for finding dependency files to scan. (e.g Filesystem Detector, GitRepositoryDetector)

- **Exporter**: Exporters take the scan results and present them in the desired format. (e.g JSONExporter, HTMLExporter, CSVExporter)
  
  > **Note**: Some examples listed above are theoretical and not yet implemented. They are provided to illustrate potential future extensions of the system.
  
## Next Features
- Support for more ecosystems
- Validation of transitive dependencies (dependencies of dependencies)  
- SBOM (Software Bill of Materials) analyzer/generator  
- Reachability analysis





