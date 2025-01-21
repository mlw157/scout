package pythonparser_test

import (
	"github.com/mlw157/scout/internal/parsers/python"
	"testing"
)

const testFilePath = "../../../testcases/parsers/python/"

// todo add more tests
func TestParsePipFile(t *testing.T) {
	t.Run("test extract correct number of dependencies", func(t *testing.T) {
		testFile := testFilePath + "requirements.txt"
		data, _ := pythonparser.ReadFile(testFile)
		dependencies, _ := pythonparser.ParseRequirementsFile(data)

		got := len(dependencies)
		want := 7

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}

	})

	t.Run("test extract correct number of dependencies unconventional file", func(t *testing.T) {
		testFile := testFilePath + "requirements-dev.txt"
		data, _ := pythonparser.ReadFile(testFile)
		dependencies, _ := pythonparser.ParseRequirementsFile(data)

		got := len(dependencies)
		want := 1

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}

	})

}
