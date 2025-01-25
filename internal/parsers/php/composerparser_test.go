package composerparser_test

import (
	composerparser "github.com/mlw157/scout/internal/parsers/php"
	"testing"
)

const testFilePath = "../../../testcases/parsers/composer/"

func TestParseComposerFile(t *testing.T) {
	t.Run("test extract correct number of dependencies", func(t *testing.T) {
		testFile := testFilePath + "composer.json"
		data, _ := composerparser.ReadFile(testFile)
		dependencies, _ := composerparser.ParseComposerJSON(data)

		got := len(dependencies)
		want := 5

		//for _, dependency := range dependencies {
		//fmt.Println(dependency)
		//}

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}
	})
}

func TestParseComposerLockFile(t *testing.T) {
	t.Run("test extract correct number of dependencies", func(t *testing.T) {
		testFile := testFilePath + "composer.lock"
		data, _ := composerparser.ReadFile(testFile)
		dependencies, _ := composerparser.ParseComposerLock(data)

		got := len(dependencies)
		want := 3

		//for _, dependency := range dependencies {
		//	fmt.Println(dependency)
		//}

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}
	})
}
