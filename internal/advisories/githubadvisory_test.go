package advisories_test

import (
	"github.com/mlw157/GoScan/internal/advisories"
	"github.com/mlw157/GoScan/internal/models"
	"os"
	"testing"
)

func TestParseResponse(t *testing.T) {
	t.Run("test extract correct number of vulnerabilities", func(t *testing.T) {
		file, _ := os.Open("../../testcases/github/github_advisory_response.json")

		defer file.Close()

		service := advisories.NewGitHubAdvisoryService()

		dependencies := []models.Dependency{
			{Name: "gogs.io/gogs", Version: "0.13.0", Language: "go", SourceFile: ""},
			{Name: "github.com/openfga/openfga", Version: "1.3.8", Language: "go", SourceFile: ""},
		}

		vulnerabilities, err := service.ParseResponse(file, dependencies)

		if err != nil {
			t.Fatal(err)
		}

		got := len(vulnerabilities)
		want := 2

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}
	})

}
