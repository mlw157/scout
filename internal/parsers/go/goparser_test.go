package goparser_test

import (
	"github.com/mlw157/scout/internal/models"
	"github.com/mlw157/scout/internal/parsers/go"
	"testing"
)

const testFilePath = "../../../testcases/parsers/go/"

func TestReadFile(t *testing.T) {
	t.Run("test can read file", func(t *testing.T) {
		testFile := testFilePath + "go.mod.test"
		_, err := goparser.ReadFile(testFile)

		if err != nil {
			t.Fatalf("Failed to read %q got err %q", testFile, err)
		}
	})

	t.Run("test nonexistent file", func(t *testing.T) {
		testFile := testFilePath + "this_file_does_not_exist"
		_, err := goparser.ReadFile(testFile)

		if err == nil {
			t.Fatalf("Expected an error for nonexistent file %q but got none", testFile)

		}
	})

}

func TestParseModFile(t *testing.T) {
	t.Run("test extract correct number of dependencies", func(t *testing.T) {
		testFile := testFilePath + "go.mod.test"
		data, _ := goparser.ReadFile(testFile)
		dependencies, _ := goparser.ParseModFile(data)
		got := len(dependencies)
		want := 11

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}
	})

	t.Run("test extract correct dependencies", func(t *testing.T) {
		testFile := testFilePath + "go.mod.test"
		data, _ := goparser.ReadFile(testFile)
		dependencies, _ := goparser.ParseModFile(data)

		assertEqualDependency(t, dependencies[0], models.Dependency{Name: "cloud.google.com/go/secretmanager", Version: "v1.14.2", Ecosystem: "go"})
		assertEqualDependency(t, dependencies[10], models.Dependency{Name: "github.com/cespare/xxhash/v2", Version: "v2.3.0", Ecosystem: "go"})

	})

	t.Run("test incorrect file format", func(t *testing.T) {
		testFile := "../../../testcases/parsers/python/requirements.txt"
		data, _ := goparser.ReadFile(testFile)
		_, err := goparser.ParseModFile(data)

		if err == nil {
			t.Fatalf("Expected an error for invalid file format %q but got none", testFile)

		}
	})

	t.Run("test file with no dependencies", func(t *testing.T) {
		testFile := testFilePath + "go.mod.test_empty"
		data, _ := goparser.ReadFile(testFile)
		dependencies, _ := goparser.ParseModFile(data)

		got := len(dependencies)
		want := 0

		if len(dependencies) != want {
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
