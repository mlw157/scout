package filesystem_test

import (
	"fmt"
	"github.com/mlw157/GoScan/internal/detectors"
	"github.com/mlw157/GoScan/internal/detectors/filesystem"
	"github.com/mlw157/GoScan/internal/models"
	"testing"
)

const testFilePath = "../../../testcases/detectors/"

func TestDetectFiles(t *testing.T) {
	t.Run("test detect correct files", func(t *testing.T) {
		detector := filesystem.NewFSDetector(nil, detectors.DefaultFilePatterns)
		files, _ := detector.DetectFiles(testFilePath)

		got := len(files)
		want := 3

		//logFiles(files)

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}
	})

	t.Run("test excluded directories", func(t *testing.T) {
		excluded := []string{"dont_scan_me"}
		detector := filesystem.NewFSDetector(excluded, detectors.DefaultFilePatterns)

		files, _ := detector.DetectFiles(testFilePath)

		got := len(files)
		want := 2

		//logFiles(files)

		if got != want {
			t.Errorf("got %d want %d", got, want)
		}

	})

	t.Run("test invalid path", func(t *testing.T) {
		detector := filesystem.NewFSDetector(nil, detectors.DefaultFilePatterns)

		_, err := detector.DetectFiles("asdsadsadas")

		//fmt.Println(err)

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
