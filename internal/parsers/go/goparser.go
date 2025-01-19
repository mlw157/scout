package goparser

import (
	"errors"
	"github.com/mlw157/Probe/internal/models"
	"golang.org/x/mod/modfile"
	"os"
)

type GoParser struct {
}

type FileData struct {
	Path string
	Data []byte
}

func NewGoParser() *GoParser {
	return &GoParser{}
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

// ParseModFile get all dependencies from go.mod file
func ParseModFile(fileData *FileData) (dependencies []models.Dependency, err error) {
	modFile, err := modfile.Parse("go.mod", fileData.Data, nil)
	if err != nil {
		return nil, errors.New("invalid file format")
	}
	for _, req := range modFile.Require {
		dependencies = append(dependencies, models.Dependency{
			Name:       req.Mod.Path,
			Version:    req.Mod.Version,
			Ecosystem:  "go",
			SourceFile: fileData.Path,
		})
	}
	return dependencies, nil
}

func (g *GoParser) ParseFile(path string) ([]models.Dependency, error) {
	fileData, err := ReadFile(path)
	if err != nil {
		return nil, err
	}

	dependencies, err := ParseModFile(fileData)

	if err != nil {
		return nil, err
	}

	return dependencies, nil
}
