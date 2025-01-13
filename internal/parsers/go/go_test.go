package goparser_test

import (
	"github.com/mlw157/GoScan/internal/models"
	"github.com/mlw157/GoScan/internal/parsers/go"
	"testing"
)

const testFilePath = "../../../testcases/go/"

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

func TestParseFile(t *testing.T) {
	t.Run("test extract correct number of dependencies", func(t *testing.T) {
		testFile := testFilePath + "go.mod.test"
		data, _ := goparser.ReadFile(testFile)
		dependencies, _ := goparser.ParseFile(data)
		got := len(dependencies)
		want := 11

		if len(dependencies) != want {
			t.Errorf("got %d dependencies wanted %d", got, want)
		}
	})

	t.Run("test extract correct dependencies", func(t *testing.T) {
		testFile := testFilePath + "go.mod.test"
		data, _ := goparser.ReadFile(testFile)
		dependencies, _ := goparser.ParseFile(data)

		AssertEqualDependency(t, dependencies[0], models.Dependency{Name: "cloud.google.com/go/secretmanager", Version: "v1.14.2", Language: "go", SourceFile: "../../../testcases/go/go.mod.test"})
		AssertEqualDependency(t, dependencies[10], models.Dependency{Name: "github.com/cespare/xxhash/v2", Version: "v2.3.0", Language: "go", SourceFile: "../../../testcases/go/go.mod.test"})

	})

	t.Run("test incorrect file format", func(t *testing.T) {
		testFile := "../../../testcases/python/requirements.txt.test"
		data, _ := goparser.ReadFile(testFile)
		_, err := goparser.ParseFile(data)

		if err == nil {
			t.Fatalf("Expected an error for invalid file format %q but got none", testFile)

		}
	})
}

func AssertEqualDependency(t testing.TB, got, want models.Dependency) {
	t.Helper()
	if got != want {
		t.Errorf("got %v want %v", got, want)
	}
}