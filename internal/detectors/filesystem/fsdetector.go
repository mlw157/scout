package filesystem

import (
	"github.com/mlw157/Probe/internal/detectors"
	"github.com/mlw157/Probe/internal/models"
	"io/fs"
	"path/filepath"
)

type FSDetector struct {
	filePatterns []detectors.FilePattern
	excludeDirs  []string
}

func NewFSDetector(excludeDirs []string, patterns []detectors.FilePattern) *FSDetector {
	return &FSDetector{filePatterns: patterns, excludeDirs: excludeDirs}
}

func (detector *FSDetector) DetectFiles(root string) ([]models.File, error) {
	var detectedFiles []models.File

	// WalkDir will use the function visit on every directory entry found
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		return detector.visit(path, d, err, &detectedFiles)
	})

	return detectedFiles, err
}

// this function will run on every directory entry, we need to pass the pointer to detectedFiles, in order to modify it
func (detector *FSDetector) visit(path string, d fs.DirEntry, err error, detectedFiles *[]models.File) error {
	if err != nil {
		return err
	}

	//fmt.Println(" ", path, d.IsDir())

	// this skips excluded directories
	for _, exclude := range detector.excludeDirs {
		if d.Name() == exclude {
			return filepath.SkipDir
		}
	}

	// for every not excluded file, try to match pattern expressions
	if !d.IsDir() {
		for _, pattern := range detector.filePatterns {
			if pattern.Regex.MatchString(d.Name()) {
				//fmt.Printf("File %s matched Pattern %v", d.Name(), pattern.Regex)
				*detectedFiles = append(*detectedFiles, models.File{
					Path:      path,
					Ecosystem: pattern.Ecosystem,
				})
			}
		}
	}

	return nil

}
