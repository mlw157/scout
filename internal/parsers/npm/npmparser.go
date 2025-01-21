package npmparser

import (
	"encoding/json"
	"errors"
	"github.com/mlw157/scout/internal/models"
	"os"
	"strings"
)

type NodeParser struct {
}

func NewNodeParser() *NodeParser {
	return &NodeParser{}
}

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

type PackageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func ParsePackageJSON(fileData *FileData) ([]models.Dependency, error) {
	var packageJSON PackageJSON
	var dependencies []models.Dependency

	if err := json.Unmarshal(fileData.Data, &packageJSON); err != nil {
		return nil, errors.New("invalid package.json format")
	}
	for name, version := range packageJSON.Dependencies {
		dependencies = append(dependencies, models.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "npm",
		})
	}

	// in case we want to differentiate dev dependencies in the future, for now add to same slice
	for name, version := range packageJSON.DevDependencies {
		dependencies = append(dependencies, models.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "npm",
		})
	}

	return dependencies, nil
}

type PackageLockJSON struct {
	LockfileVersion int                           `json:"lockfileVersion"`
	Packages        map[string]PackageLockPackage `json:"packages"`
}

type PackageLockPackage struct {
	Name            string            `json:"name,omitempty"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies,omitempty"`
	DevDependencies map[string]string `json:"devDependencies,omitempty"`
}

func ParsePackageLockJSON(fileData *FileData) ([]models.Dependency, error) {
	var packageLock PackageLockJSON
	var dependencies []models.Dependency

	if err := json.Unmarshal(fileData.Data, &packageLock); err != nil {
		return nil, errors.New("invalid package-lock.json format")
	}

	for path, pkg := range packageLock.Packages {
		name := strings.TrimPrefix(path, "node_modules/")

		// Skip if there's no version (shouldn't happen in valid package-lock.json)
		if pkg.Version == "" {
			continue
		}

		dependencies = append(dependencies, models.Dependency{
			Name:      name,
			Version:   pkg.Version,
			Ecosystem: "npm",
		})
	}

	return dependencies, nil
}

func (n *NodeParser) ParseFile(path string) ([]models.Dependency, error) {
	fileData, err := ReadFile(path)
	if err != nil {
		return nil, err
	}

	var dependencies []models.Dependency

	// decide to use package.json or package-lock.json parser
	if strings.HasSuffix(path, "package.json") {
		dependencies, err = ParsePackageJSON(fileData)

	} else if strings.HasSuffix(path, "package-lock.json") {
		dependencies, err = ParsePackageLockJSON(fileData)

	} else {
		return nil, errors.New("unsupported file type")
	}

	if err != nil {
		return nil, err
	}

	return dependencies, nil
}
