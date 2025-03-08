package db

import (
	"encoding/json"
	"fmt"
	"github.com/Masterminds/semver"
	"github.com/mlw157/scout/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type DatabaseAdvisoryService struct {
	DB     *gorm.DB
	Update bool
}

const databaseURL = "https://github.com/mlw157/scout-db/raw/main/scout.db"

func downloadDatabase(databasePath string) error {
	log.Printf("Downloading the latest vulnerability database...\n")

	resp, err := http.Get(databaseURL)
	if err != nil {
		return fmt.Errorf("failed to download database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download database, status code: %d", resp.StatusCode)
	}

	out, err := os.Create(databasePath)
	if err != nil {
		return fmt.Errorf("failed to create database file: %w", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save database file: %w", err)
	}

	log.Printf("Vulnerability database successfully updated\n")
	return nil
}

func NewDatabaseAdvisoryService(databasePath string, update bool) (*DatabaseAdvisoryService, error) {
	if update {
		if err := downloadDatabase(databasePath); err != nil {
			return nil, err
		}
	}
	if _, err := os.Stat(databasePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("advisory: database file %s does not exist", databasePath)
	}

	db, err := gorm.Open(sqlite.Open(databasePath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("advisory: failed to connect to database: %w", err)
	}

	return &DatabaseAdvisoryService{DB: db}, nil
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func (d *DatabaseAdvisoryService) FetchVulnerabilities(dependencies []models.Dependency) ([]models.Vulnerability, error) {
	if len(dependencies) == 0 {
		return nil, nil
	}

	var vulnerabilities []models.Vulnerability

	for _, dependency := range dependencies {
		var advisories []Advisory

		d.DB.Config.Logger = logger.Default.LogMode(logger.Error)
		result := d.DB.Where("ecosystem = ? AND package = ?", dependency.Ecosystem, dependency.Name).Find(&advisories)
		if result.Error != nil {
			return nil, fmt.Errorf("advisory: query failed: %w", result.Error)
		}

		for _, advisory := range advisories {
			if IsVersionVulnerable(dependency.Version, advisory.VersionRange) {
				var references []string
				if advisory.References != "" {
					var refs []Reference
					err := json.Unmarshal([]byte(advisory.References), &refs)
					if err != nil {
						log.Printf("advisory: failed to parse references for advisory %s: %v\n", advisory.ID, err)
					}

					for _, ref := range refs {
						references = append(references, ref.URL)
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

func normalizeVersion(version string) (string, error) {
	// make them acceptable according to https://github.com/Masterminds/semver/blob/master/README.md
	version = strings.ReplaceAll(version, ".Beta", "-beta.")
	version = strings.ReplaceAll(version, ".beta", "-beta.")
	version = strings.ReplaceAll(version, ".Alpha", "-alpha.")
	version = strings.ReplaceAll(version, ".alpha", "-alpha.")
	version = strings.ReplaceAll(version, ".RC", "-rc.")
	version = strings.ReplaceAll(version, ".rc", "-rc.")

	re := regexp.MustCompile(`^(\d+\.\d+\.\d+)\.\d+$`)
	if matches := re.FindStringSubmatch(version); len(matches) > 1 {
		version = matches[1]
	}
	_, err := semver.NewVersion(version)
	if err != nil {
		return "", fmt.Errorf("invalid version: %s", version)
	}

	return version, nil
}

// fixConstraintFormat fixes compound constraints
func fixConstraintFormat(constraint string) string {
	parts := strings.Fields(constraint)
	return strings.Join(parts, ", ")
}

func IsVersionVulnerable(version, versionRange string) bool {
	if versionRange == "all versions" {
		return true
	}
	cleanVersion := strings.TrimLeft(version, "^~><= ")

	ver, err := semver.NewVersion(cleanVersion)
	if err != nil {
		log.Printf("skipping dependency version %s: %v\n", cleanVersion, err)
		return false
	}

	ranges := strings.Split(versionRange, " OR ")

	for _, r := range ranges {
		r = strings.TrimSpace(r)
		fixedConstraint := fixConstraintFormat(r)

		re := regexp.MustCompile(`(\d+\.\d+\.\d+(?:[-.][A-Za-z0-9]+)*)`)
		normalizedConstraint := re.ReplaceAllStringFunc(fixedConstraint, func(match string) string {
			normalized, err := normalizeVersion(match)
			if err != nil {
				log.Printf("could not normalize version %s: %v\n", match, err)
				return match
			}
			return normalized
		})

		constraint, err := semver.NewConstraint(normalizedConstraint)
		if err != nil {
			// log.Printf("advisory: error parsing version constraint %s: %v\n", normalizedConstraint, err)
			continue
		}

		if constraint.Check(ver) {
			return true
		}
	}
	return false
}
