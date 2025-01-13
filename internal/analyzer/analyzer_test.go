package analyzer_test

import (
	"reflect"
	"testing"
)
import "github.com/mlw157/GoScan/internal/models"
import "github.com/mlw157/GoScan/internal/analyzer"

func TestAnalyzer(t *testing.T) {
	t.Run("test analyzer", func(t *testing.T) {
		dependencies := []models.Dependency{
			{Name: "cloud.google.com/go/secretmanager", Version: "v1.14.2", Language: "go", SourceFile: "go.mod.test"},
			{Name: "cloud.google.com/go/storage", Version: "v1.48.0", Language: "go", SourceFile: "go.mod.test"}}

		got, _ := analyzer.AnalyzeDependencies(nil, dependencies)
		var want []models.Vulnerability

		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v want %v", got, want)
		}
	})
}
