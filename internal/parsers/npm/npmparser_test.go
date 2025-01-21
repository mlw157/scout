package npmparser_test

import (
	npmparser "github.com/mlw157/scout/internal/parsers/npm"
	"testing"
)

const testFilePath = "../../../testcases/parsers/npm/"

// todo add more tests
func TestParsePackageFile(t *testing.T) {
	t.Run("test extract correct number of dependencies", func(t *testing.T) {
		testFile := testFilePath + "package.json"
		data, _ := npmparser.ReadFile(testFile)
		dependencies, _ := npmparser.ParsePackageJSON(data)

		got := len(dependencies)
		want := 20

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}

	})

}

func TestParsePackageLockFile(t *testing.T) {
	t.Run("test extract correct number of dependencies", func(t *testing.T) {
		testFile := testFilePath + "package-lock.json"
		data, _ := npmparser.ReadFile(testFile)
		dependencies, _ := npmparser.ParsePackageLockJSON(data)

		//for _, dependency := range dependencies {
		//	fmt.Println(dependency)
		//}

		got := len(dependencies)
		want := 953

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}

	})

}
