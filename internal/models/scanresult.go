package models

type ScanResult struct {
	Dependencies    []Dependency
	Vulnerabilities []Vulnerability
}
