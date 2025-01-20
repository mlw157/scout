package mavenparser

import (
	"encoding/xml"
	"errors"
	"github.com/mlw157/Scout/internal/models"
	"os"
)

type MavenParser struct {
}

type FileData struct {
	Path string
	Data []byte
}

func NewMavenParser() *MavenParser {
	return &MavenParser{}
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

type MavenDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type MavenDependencyManagement struct {
	XMLName      xml.Name          `xml:"dependencyManagement"`
	Dependencies []MavenDependency `xml:"dependencies>dependency"`
}

type MavenDependencies struct {
	XMLName    xml.Name          `xml:"dependencies"`
	Dependency []MavenDependency `xml:"dependency"`
}

type MavenPOM struct {
	XMLName              xml.Name                   `xml:"project"`
	DependencyManagement *MavenDependencyManagement `xml:"dependencyManagement"`
	Dependencies         MavenDependencies          `xml:"dependencies"`
}

// ParsePomFile get all dependencies from pom.xml file
func ParsePomFile(fileData *FileData) ([]models.Dependency, error) {
	var dependencies []models.Dependency

	var pom MavenPOM
	err := xml.Unmarshal(fileData.Data, &pom)
	if err != nil {
		return nil, errors.New("invalid pom file format")
	}

	// Add dependencies from the <dependencies> section
	for _, dep := range pom.Dependencies.Dependency {
		dependencies = append(dependencies, models.Dependency{
			Name:      dep.GroupID + ":" + dep.ArtifactID,
			Version:   dep.Version,
			Ecosystem: "maven",
		})
	}

	// Add dependencies from the <dependencyManagement> section
	if pom.DependencyManagement != nil {
		for _, dep := range pom.DependencyManagement.Dependencies {
			dependencies = append(dependencies, models.Dependency{
				Name:      dep.GroupID + ":" + dep.ArtifactID,
				Version:   dep.Version,
				Ecosystem: "maven",
			})
		}
	}

	return dependencies, nil
}

func (m *MavenParser) ParseFile(path string) ([]models.Dependency, error) {
	fileData, err := ReadFile(path)

	if err != nil {
		return nil, err
	}

	dependencies, err := ParsePomFile(fileData)
	if err != nil {
		return nil, err
	}

	return dependencies, nil
}
