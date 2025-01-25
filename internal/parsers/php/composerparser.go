package composerparser

import (
	"encoding/json"
	"errors"
	"github.com/mlw157/scout/internal/models"
	"os"
	"strings"
)

type ComposerParser struct {
}

type FileData struct {
	Path string
	Data []byte
}

func NewComposerParser() *ComposerParser {
	return &ComposerParser{}
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

type ComposerJSON struct {
	RequireDev map[string]string `json:"require-dev"`
	Require    map[string]string `json:"require"`
}

type ComposerLock struct {
	Packages    []ComposerPackage `json:"packages"`
	PackagesDev []ComposerPackage `json:"packages-dev"`
}

type ComposerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func ParseComposerJSON(fileData *FileData) ([]models.Dependency, error) {
	var composerJSON ComposerJSON
	var dependencies []models.Dependency

	if err := json.Unmarshal(fileData.Data, &composerJSON); err != nil {
		return nil, errors.New("invalid composer.json format")
	}

	for name, version := range composerJSON.Require {
		dependencies = append(dependencies, models.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "composer",
		})
	}

	// in case we want to differentiate dev dependencies in the future, for now add to same slice
	for name, version := range composerJSON.RequireDev {
		dependencies = append(dependencies, models.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "composer",
		})
	}

	return dependencies, nil
}

func ParseComposerLock(fileData *FileData) ([]models.Dependency, error) {
	var composerLock ComposerLock
	var dependencies []models.Dependency

	if err := json.Unmarshal(fileData.Data, &composerLock); err != nil {
		return nil, errors.New("invalid composer.lock format")
	}

	for _, pkg := range composerLock.Packages {
		dependencies = append(dependencies, models.Dependency{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: "composer",
		})
	}

	// in case we want to differentiate dev dependencies in the future, for now add to same slice
	for _, pkg := range composerLock.PackagesDev {
		dependencies = append(dependencies, models.Dependency{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: "composer",
		})
	}

	return dependencies, nil
}

func (c *ComposerParser) ParseFile(path string) ([]models.Dependency, error) {
	fileData, err := ReadFile(path)
	if err != nil {
		return nil, err
	}

	var dependencies []models.Dependency

	// decide to use composer.json or composer.lock parser
	if strings.HasSuffix(path, "composer.json") {
		dependencies, err = ParseComposerJSON(fileData)
	} else if strings.HasSuffix(path, "composer.lock") {
		dependencies, err = ParseComposerLock(fileData)
	} else {
		return nil, errors.New("unsupported file type")
	}

	if err != nil {
		return nil, err
	}

	return dependencies, nil
}
