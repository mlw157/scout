package rustparser_test

import (
	"testing"

	"github.com/mlw157/scout/internal/models"
	rustparser "github.com/mlw157/scout/internal/parsers/rust"
)

const testFilePath = "../../../testcases/parsers/rust/"

func TestParseCargoLock(t *testing.T) {
	t.Run("test extract correct number of dependencies", func(t *testing.T) {
		testFile := testFilePath + "Cargo.lock"
		parser := rustparser.NewRustParser()
		dependencies, err := parser.ParseFile(testFile)

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		got := len(dependencies)
		want := 5

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}
	})

	t.Run("test extract correct dependencies", func(t *testing.T) {
		testFile := testFilePath + "Cargo.lock"
		parser := rustparser.NewRustParser()
		dependencies, _ := parser.ParseFile(testFile)

		assertEqualDependency(t, dependencies[0], models.Dependency{Name: "hyper", Version: "0.14.18", Ecosystem: "crates.io"})
		assertEqualDependency(t, dependencies[1], models.Dependency{Name: "regex", Version: "1.5.4", Ecosystem: "crates.io"})
	})

	t.Run("test file with no dependencies", func(t *testing.T) {
		testFile := testFilePath + "Cargo.lock.empty"
		parser := rustparser.NewRustParser()
		dependencies, err := parser.ParseFile(testFile)

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		got := len(dependencies)
		want := 0

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}
	})

}

func assertEqualDependency(t testing.TB, got, want models.Dependency) {
	t.Helper()
	if got != want {
		t.Errorf("got %v want %v", got, want)
	}
}
