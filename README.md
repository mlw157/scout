# Scout

Scout is a lightweight Software Composition Analysis (SCA) tool. It analyzes your project's dependencies and checks them against known vulnerabilities.

## Ecosystemes Supported so far

**Go**: Scans go.mod files for vulnerabilities in Go dependencies.<br/>
**Maven**: Scans pom.xml files for vulnerabilities in Maven dependencies.

## Installation
### Option 1: Pull the Docker Image from GitHub Container Registry

If you want to quickly use scout without building it from the source, you can pull the pre-built Docker image directly from the GitHub Container Registry.

```bash
docker pull ghcr.io/mlw157/scout:latest
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
| `-ecosystems` | Ecosystems to scan | `all supported ones` | `-ecosystems=maven,pip` |
| `-exclude` | File/Directory patterns to exclude | - | `-exclude=node_modules,.git` |
| `-export` | Export JSON report | `false` | `-export` |
| `-token` | GitHub API token | - | `-token=ghp_123abc...` |
### Why Include a GitHub Token?

It isn't necessary to use a GitHub token but, by default, unauthenticated requests to the GitHub API are limited to 60 requests per hour per IP. <br/>
If you include a GitHub token, your request limit increases to 5000 requests per hour, which is especially useful if you are scanning large or multiple repositories. (Scout makes a request for every dependency file or every 100 dependencies detected) <br/>
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
Export results to scout_report.json
```bash
docker run --rm -v "${PWD}:/scan" scout:latest -ecosystems maven -export .
```
Exclude subdirectories or files
```bash
docker run --rm -v "${PWD}:/scan" scout:latest -exclude tests,package-lock.json .
```
Exclude subdirectories or files
```bash
docker run --rm -v "${PWD}:/scan" scout:latest -token ghp_123abc12rasdasdsa .
```

## Next Features

- Support for more ecosystems (Python, npm, PHP, etc...)  
- Validation of transitive dependencies (dependencies of dependencies)  
- SBOM (Software Bill of Materials) analyzer  
- Reachability analysis


