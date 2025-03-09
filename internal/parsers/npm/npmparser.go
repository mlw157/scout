package npmparser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"github.com/mlw157/scout/internal/models"
	"os"
	"strings"
)

type NodeParser struct{}

func NewNodeParser() *NodeParser {
	return &NodeParser{}
}

type FileData struct {
	Path string
	Data []byte
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
	Name    string `json:"name,omitempty"`
	Version string `json:"version"`
}

func ParsePackageLockJSON(fileData *FileData) ([]models.Dependency, error) {
	var packageLock PackageLockJSON
	var dependencies []models.Dependency

	if err := json.Unmarshal(fileData.Data, &packageLock); err != nil {
		return nil, errors.New("invalid package-lock.json format")
	}

	for path, pkg := range packageLock.Packages {
		name := strings.TrimPrefix(path, "node_modules/")
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

func ParseYarnLock(fileData *FileData) ([]models.Dependency, error) {
	var dependencies []models.Dependency
	scanner := bufio.NewScanner(bytes.NewReader(fileData.Data))

	// track the current package being processed
	var currentPackage string

	for scanner.Scan() {
		line := scanner.Text()

		// package lines end with :
		if strings.HasSuffix(line, ":") {
			// extract the package name from between quotes if present
			packageLine := strings.Trim(line[:len(line)-1], "\"")

			if idx := strings.LastIndex(packageLine, "@"); idx > 0 {
				if packageLine[0] == '@' {
					secondAt := strings.Index(packageLine[1:], "@")
					if secondAt > 0 {
						currentPackage = packageLine[:secondAt+1] // +1 because we started at index 1
					} else {
						currentPackage = packageLine
					}
				} else {
					currentPackage = packageLine[:idx]
				}
			} else {
				currentPackage = packageLine
			}
		} else if strings.HasPrefix(line, "  version ") {
			if currentPackage != "" {
				version := strings.Trim(strings.TrimPrefix(line, "  version "), "\"")

				dependencies = append(dependencies, models.Dependency{
					Name:      currentPackage,
					Version:   version,
					Ecosystem: "npm",
				})
				currentPackage = ""
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return dependencies, nil
}

func (n *NodeParser) ParseFile(path string) ([]models.Dependency, error) {
	fileData, err := ReadFile(path)
	if err != nil {
		return nil, err
	}

	var dependencies []models.Dependency

	switch {
	case strings.HasSuffix(path, "package.json"):
		dependencies, err = ParsePackageJSON(fileData)
	case strings.HasSuffix(path, "package-lock.json"):
		dependencies, err = ParsePackageLockJSON(fileData)
	case strings.HasSuffix(path, "yarn.lock"):
		dependencies, err = ParseYarnLock(fileData)
	default:
		return nil, errors.New("unsupported file type")
	}

	if err != nil {
		return nil, err
	}
	return dependencies, nil
}
