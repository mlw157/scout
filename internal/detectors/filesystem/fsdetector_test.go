package filesystem_test

import (
	"fmt"
	"github.com/mlw157/scout/internal/detectors/filesystem"
	"github.com/mlw157/scout/internal/models"
	"testing"
)

const testFilePath = "../../../testcases/detectors/"

func TestDetectFiles(t *testing.T) {
	detector := filesystem.NewFSDetector()
	t.Run("test detect correct files", func(t *testing.T) {
		files, _ := detector.DetectFiles(testFilePath, nil, nil)

		got := len(files)
		want := 3

		//logFiles(files)

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}
	})

	t.Run("test excluded directories", func(t *testing.T) {
		excluded := []string{"dont_scan_me"}

		files, _ := detector.DetectFiles(testFilePath, excluded, nil)

		got := len(files)
		want := 2

		//logFiles(files)

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}

	})

	t.Run("test specified ecosystems", func(t *testing.T) {
		ecosystems := []string{"maven"}
		files, _ := detector.DetectFiles(testFilePath, nil, ecosystems)

		got := len(files)
		want := 1

		//logFiles(files)

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}

	})

	t.Run("test invalid path", func(t *testing.T) {
		_, err := detector.DetectFiles("asdsadsadas", nil, nil)

		fmt.Println(err)

		if err == nil {
			t.Fatalf("Expected an error for nonexistent directory but got none")

		}

	})
}

func logFiles(files []models.File) {
	for _, file := range files {
		fmt.Println(file)
	}
}
