package pythonparser_test

import (
	"testing"

	pythonparser "github.com/mlw157/scout/internal/parsers/python"
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

func TestParsePoetryLock(t *testing.T) {
	t.Run("test extract correct number of dependencies from poetry.lock", func(t *testing.T) {
		testFile := testFilePath + "poetry.lock"
		data, err := pythonparser.ReadFile(testFile)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		dependencies, err := pythonparser.ParsePoetryLock(data)
		if err != nil {
			t.Fatalf("failed to parse poetry.lock: %v", err)
		}

		got := len(dependencies)
		want := 5

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}
	})

	t.Run("test poetry.lock dependencies have correct ecosystem", func(t *testing.T) {
		testFile := testFilePath + "poetry.lock"
		data, _ := pythonparser.ReadFile(testFile)
		dependencies, _ := pythonparser.ParsePoetryLock(data)

		for _, dep := range dependencies {
			if dep.Ecosystem != "pip" {
				t.Errorf("expected ecosystem 'pip', got '%s'", dep.Ecosystem)
			}
		}
	})

	t.Run("test poetry.lock contains expected packages", func(t *testing.T) {
		testFile := testFilePath + "poetry.lock"
		data, _ := pythonparser.ReadFile(testFile)
		dependencies, _ := pythonparser.ParsePoetryLock(data)

		expectedPackages := map[string]string{
			"certifi":            "2023.7.22",
			"charset-normalizer": "3.2.0",
			"idna":               "3.4",
			"requests":           "2.31.0",
			"urllib3":            "2.0.4",
		}

		foundPackages := make(map[string]string)
		for _, dep := range dependencies {
			foundPackages[dep.Name] = dep.Version
		}

		for name, version := range expectedPackages {
			if foundVersion, ok := foundPackages[name]; !ok {
				t.Errorf("expected package %s not found", name)
			} else if foundVersion != version {
				t.Errorf("package %s: expected version %s, got %s", name, version, foundVersion)
			}
		}
	})
}

func TestPipParserParseFile(t *testing.T) {
	parser := pythonparser.NewPipParser()

	t.Run("test ParseFile routes poetry.lock correctly", func(t *testing.T) {
		testFile := testFilePath + "poetry.lock"
		dependencies, err := parser.ParseFile(testFile)
		if err != nil {
			t.Fatalf("failed to parse poetry.lock: %v", err)
		}

		got := len(dependencies)
		want := 5

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}
	})

	t.Run("test ParseFile routes requirements.txt correctly", func(t *testing.T) {
		testFile := testFilePath + "requirements.txt"
		dependencies, err := parser.ParseFile(testFile)
		if err != nil {
			t.Fatalf("failed to parse requirements.txt: %v", err)
		}

		got := len(dependencies)
		want := 7

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}
	})
}
