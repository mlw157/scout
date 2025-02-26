package db

import (
	"encoding/json"
	"fmt"
	"github.com/Masterminds/semver"
	"github.com/mlw157/scout/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"log"
	"strings"
)

type DatabaseAdvisoryService struct {
	DB *gorm.DB
}

func NewDatabaseAdvisoryService(databasePath string) (*DatabaseAdvisoryService, error) {
	db, err := gorm.Open(sqlite.Open(databasePath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("advisory: failed to connect to database: %w", err)
	}

	return &DatabaseAdvisoryService{DB: db}, nil
}

func (d *DatabaseAdvisoryService) FetchVulnerabilities(dependencies []models.Dependency) ([]models.Vulnerability, error) {
	if len(dependencies) == 0 {
		return nil, nil
	}

	var vulnerabilities []models.Vulnerability

	for _, dependency := range dependencies {
		var advisories []DatabaseAdvisory

		result := d.DB.Where("ecosystem = ? AND package = ?", dependency.Ecosystem, dependency.Name).Find(&advisories)
		if result.Error != nil {
			return nil, fmt.Errorf("advisory: query failed: %w", result.Error)
		}

		for _, advisory := range advisories {
			if IsVersionVulnerable(dependency.Version, advisory.VersionRange) {
				var references []string
				if advisory.References != "" {
					err := json.Unmarshal([]byte(advisory.References), &references)
					if err != nil {
						log.Printf("advisory: failed to parse references for advisory %s: %v\n", advisory.ID, err)
					}
				}
				vulnerability := models.Vulnerability{
					Dependency:             dependency,
					Severity:               advisory.Severity,
					CVE:                    advisory.CVE,
					Summary:                advisory.Summary,
					Description:            advisory.Details,
					URL:                    "https://github.com/advisories/" + advisory.ID,
					VulnerableVersionRange: advisory.VersionRange,
					FirstPatchedVersion:    advisory.FirstPatchedVersion,
					References:             references,
				}
				vulnerabilities = append(vulnerabilities, vulnerability)
			}
		}
	}
	return vulnerabilities, nil
}

func IsVersionVulnerable(version, versionRange string) bool {
	if versionRange == "all versions" {
		return true
	}

	ver, err := semver.NewVersion(version)
	if err != nil {
		fmt.Printf("advisory: error parsing dependency version %s: %v\n", version, err)
		return false
	}

	ranges := strings.Split(versionRange, " OR ")

	for _, r := range ranges {
		r = strings.TrimSpace(r)
		r = strings.ReplaceAll(r, " ", ", ")

		constraint, err := semver.NewConstraint(r)
		if err != nil {
			log.Printf("advisory: error parsing version constraint %s: %v\n", r, err)
			continue
		}

		if constraint.Check(ver) {
			return true
		}
	}
	return false
}
