package pythonparser

import (
	"bufio"
	"errors"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/mlw157/scout/internal/models"
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

func ParseRequirementsFile(fileData *FileData) ([]models.Dependency, error) {
	var dependencies []models.Dependency

	scanner := bufio.NewScanner(strings.NewReader(string(fileData.Data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// remove comments
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}
		if strings.HasPrefix(line, "#") {
			continue
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

type PoetryLock struct {
	Package []PoetryPackage `toml:"package"`
}

type PoetryPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

func ParsePoetryLock(fileData *FileData) ([]models.Dependency, error) {
	var poetryLock PoetryLock
	var dependencies []models.Dependency

	if err := toml.Unmarshal(fileData.Data, &poetryLock); err != nil {
		return nil, errors.New("invalid poetry.lock file format")
	}

	for _, pkg := range poetryLock.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		dependencies = append(dependencies, models.Dependency{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: "pip",
		})
	}

	return dependencies, nil
}

func (g *PipParser) ParseFile(path string) ([]models.Dependency, error) {
	fileData, err := ReadFile(path)
	if err != nil {
		return nil, err
	}

	var dependencies []models.Dependency

	switch {
	case strings.HasSuffix(path, "poetry.lock"):
		dependencies, err = ParsePoetryLock(fileData)
	default:
		// Handle requirements.txt and similar files
		dependencies, err = ParseRequirementsFile(fileData)
	}

	if err != nil {
		return nil, err
	}

	return dependencies, nil
}
