package goparser

import (
	"errors"
	"github.com/mlw157/GoScan/internal/models"
	"golang.org/x/mod/modfile"
	"os"
)

type FileData struct {
	Path string
	Data []byte
}

// ReadFile returns data of file given path
func ReadFile(path string) (*FileData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return &FileData{
		Path: path,
		Data: data,
	}, nil
}

// ParseFile get all dependencies from go.mod file
func ParseFile(fileData *FileData) (dependencies []models.Dependency, err error) {
	modFile, err := modfile.Parse("go.mod", fileData.Data, nil)
	if err != nil {
		return nil, errors.New("invalid file format")
	}
	for _, req := range modFile.Require {
		dependencies = append(dependencies, models.Dependency{
			Name:       req.Mod.Path,
			Version:    req.Mod.Version,
			Language:   "go",
			SourceFile: fileData.Path,
		})
	}
	return dependencies, nil
}
