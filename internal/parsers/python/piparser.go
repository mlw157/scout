package python

import (
	"bufio"
	"errors"
	"github.com/mlw157/scout/internal/models"
	"os"
	"strings"
)

type PipParser struct {
}

type FileData struct {
	Path string
	Data []byte
}

func NewPipParser() *PipParser {
	return &PipParser{}
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

// ParseRequirementsFile extracts all dependencies from a requirements.txt file
func ParseRequirementsFile(fileData *FileData) ([]models.Dependency, error) {
	var dependencies []models.Dependency

	scanner := bufio.NewScanner(strings.NewReader(string(fileData.Data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // skip empty and commented
		}

		split := strings.Split(line, "==")
		name := split[0]
		version := ""
		if len(split) > 1 {
			version = split[1]

			dependencies = append(dependencies, models.Dependency{
				Name:      name,
				Version:   version,
				Ecosystem: "pip",
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, errors.New("invalid requirements.txt file format")
	}

	return dependencies, nil
}

func (g *PipParser) ParseFile(path string) ([]models.Dependency, error) {
	fileData, err := ReadFile(path)
	if err != nil {
		return nil, err
	}

	dependencies, err := ParseRequirementsFile(fileData)

	if err != nil {
		return nil, err
	}

	return dependencies, nil
}
