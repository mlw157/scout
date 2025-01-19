package gh_test

import (
	"fmt"
	"github.com/mlw157/Probe/internal/advisories/gh"
	"github.com/mlw157/Probe/internal/models"
	"os"
	"reflect"
	"testing"
)

// todo make worst case tests (mix of ecosystems, pagination, http errors)
func TestParseResponse(t *testing.T) {
	service := gh.NewGitHubAdvisoryService()

	t.Run("test extract correct number of vulnerabilities", func(t *testing.T) {
		file, _ := os.Open("../../../testcases/advisories/github/github_advisory_response.json")

		defer file.Close()

		dependencies := []models.Dependency{
			{Name: "gogs.io/gogs", Version: "0.13.0", Ecosystem: "go"},
			{Name: "github.com/openfga/openfga", Version: "1.3.8", Ecosystem: "go"},
		}

		vulnerabilities, err := service.ParseResponse(file, dependencies)

		//logVulnerabilities(vulnerabilities)

		if err != nil {
			t.Fatal(err)
		}

		got := len(vulnerabilities)
		want := 9

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}
	})

	t.Run("test extract correct vulnerabilities", func(t *testing.T) {
		file, _ := os.Open("../../../testcases/advisories/github/github_advisory_response.json")
		defer file.Close()

		dependencies := []models.Dependency{
			{Name: "gogs.io/gogs", Version: "0.13.0", Ecosystem: "go"},
			{Name: "github.com/openfga/openfga", Version: "1.3.8", Ecosystem: "go"},
		}

		vulnerabilities, err := service.ParseResponse(file, dependencies)

		//logVulnerabilities(vulnerabilities)

		if err != nil {
			t.Fatal(err)
		}

		vulnerabilities[0].References = nil
		vulnerabilities[0].Description = ""
		vulnerabilities[0].VulnerableFunctions = nil
		vulnerabilities[8].References = nil
		vulnerabilities[8].Description = ""
		vulnerabilities[8].VulnerableFunctions = nil

		assertEqualVulnerability(t, vulnerabilities[0], models.Vulnerability{
			Dependency:             dependencies[1],
			Severity:               "medium",
			CVE:                    "CVE-2024-56323",
			Summary:                "OpenFGA Authorization Bypass",
			Description:            "",
			URL:                    "https://api.github.com/advisories/GHSA-32q6-rr98-cjqv",
			VulnerableVersionRange: ">= 1.3.8, < 1.8.3",
			FirstPatchedVersion:    "1.8.3",
			References:             nil,
			VulnerableFunctions:    nil,
		})
		assertEqualVulnerability(t, vulnerabilities[8], models.Vulnerability{
			Dependency:             dependencies[1],
			Severity:               "medium",
			CVE:                    "CVE-2024-23820",
			Summary:                "OpenFGA denial of service",
			Description:            "",
			URL:                    "https://api.github.com/advisories/GHSA-rxpw-85vw-fx87",
			VulnerableVersionRange: "< 1.4.3",
			FirstPatchedVersion:    "1.4.3",
			References:             nil,
			VulnerableFunctions:    nil,
		})

	})

}

func logVulnerabilities(vulnerabilities []models.Vulnerability) {
	for _, vulnerability := range vulnerabilities {
		fmt.Printf("Package %v version %v has %v\n", vulnerability.Dependency.Name, vulnerability.Dependency.Version, vulnerability.CVE)
	}
}

func assertEqualVulnerability(t testing.TB, got, want models.Vulnerability) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}
