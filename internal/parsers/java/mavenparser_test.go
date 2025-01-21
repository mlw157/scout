package mavenparser_test

import (
	mavenparser "github.com/mlw157/scout/internal/parsers/java"
	"testing"
)

const testFilePath = "../../../testcases/parsers/maven/"

// todo add more tests
func TestParsePomFile(t *testing.T) {
	t.Run("test extract correct number of dependencies", func(t *testing.T) {
		testFile := testFilePath + "pom.xml"
		data, _ := mavenparser.ReadFile(testFile)
		dependencies, _ := mavenparser.ParsePomFile(data)

		got := len(dependencies)
		want := 6

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}

	})

}
