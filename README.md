# Scout

Scout is a lightweight Software Composition Analysis (SCA) tool. It analyzes your project's dependencies and checks them against known vulnerabilities.
## Ecosystems Supported so far

**Go**: Scans go.mod files for vulnerabilities in Go dependencies.<br/>
**Maven**: Scans pom.xml files for vulnerabilities in Maven dependencies.<br/>
**Python**: Scans requirements.txt files for vulnerabilities in pip dependencies.<br/>
**NPM**: Scans package.json and package-lock.json files for vulnerabilities in npm dependencies.<br/>
**Composer**: Scans composer.json and composer.lock files for vulnerabilities in composer dependencies.<br/>

## Installation
### Option 1: Pull the Docker Image from GitHub Container Registry

If you want to quickly use scout without building it from the source, you can pull the pre-built Docker image directly from the GitHub Container Registry.

```bash
docker pull ghcr.io/mlw157/scout:latest
```
```bash
docker tag ghcr.io/mlw157/scout:latest scout:latest
```
### Option 2: Build from Source

If you prefer building the Docker image locally: <br/>
<br/>
Clone the repository to your local machine:
```bash
git clone https://github.com/mlw157/scout.git
cd scout
```
Build the Docker image locally:
```bash
docker build -t scout:latest .
```
## Usage
Once the image is pulled or built, you can run scout inside a Docker container.
### Command-Line Flags

| Flag | Description | Default | Example |
| --- | --- | --- | --- |
| `-ecosystems` | Ecosystems to scan | `all supported ones` | `-ecosystems maven,pip` |
| `-exclude` | File/Directory patterns to exclude | - | `-exclude node_modules,.git` |
| `-export` | Export JSON report | `false` | `-export` |
| `-format` | Export format | `json` | `-format dojo` |
| `-output` | Output file path | `[format]` | `-output custom_report.json` |
| `-token` | GitHub API token | - | `-token ghp_123abc...` |
### Why include a GitHub Token?

It isn't necessary to use a GitHub token but, by default, unauthenticated requests to the GitHub API are limited to 60 requests per hour per IP. If surpassed, scout will fail to analyze dependencies and return unexpected errors. <br/>
If you include a GitHub token, your request limit increases to 5000 requests per hour, which is especially useful if you are scanning large or multiple repositories. (Scout makes a request for every dependency file or every 50 dependencies detected) <br/>
<br/>
A GitHub App token that is owned by a GitHub Enterprise Cloud has a even bigger limit of 15000 requests per hour.<br/>
<br/>
https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api

### Example
Scan current directory for all ecosystems, without excluding any subdirectories and files
```bash
docker run --rm -v "${PWD}:/scan" scout:latest .
```
Scan current directory for only maven dependencies
```bash
docker run --rm -v "${PWD}:/scan" scout:latest -ecosystems maven .
```
Export results to default scout_report.json
```bash
docker run --rm -v "${PWD}:/scan" scout:latest -ecosystems maven -export .
```
Export results to defect dojo format
```bash
docker run --rm -v "${PWD}:/scan" scout:latest -ecosystems maven -export -format dojo .
```
Exclude subdirectories or files
```bash
docker run --rm -v "${PWD}:/scan" scout:latest -exclude tests,package-lock.json .
```
Use GitHub token
```bash
docker run --rm -v "${PWD}:/scan" scout:latest -token ghp_123abc12rasdasdsa .
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

- **Exporter**: Exporters take the scan results and present them in the desired format. (e.g JSONExporter, HTMLExporter, CSVExporter)
  
  > **Note**: Some examples listed above are theoretical and not yet implemented. They are provided to illustrate potential future extensions of the system.
  
## Next Features
- Support for more ecosystems
- Validation of transitive dependencies (dependencies of dependencies)  
- SBOM (Software Bill of Materials) analyzer/generator  
- Reachability analysis
- Typo Squatting analysis 




