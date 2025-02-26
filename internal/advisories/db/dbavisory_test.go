package db_test

import (
	"github.com/mlw157/scout/internal/advisories/db"
	"github.com/mlw157/scout/internal/models"
	"reflect"
	"testing"
)

// todo tests (how to simulate db?)
func TestFetchVulnerabilities(t *testing.T) {

}

func TestIsVersionVulnerable(t *testing.T) {
	testCases := []struct {
		version      string
		versionRange string
		want         bool
	}{
		{"1.2.3", "all versions", true},
		{"1.2.3", ">=1.0.0 <2.0.0", true},
		{"2.0.0", ">=1.0.0 <2.0.0", false},
		{"1.5.0", "<=1.5.0", true},
		{"1.6.0", "<=1.5.0", false},
		{"1.0.0", "1.0.0", true},
		{"1.0.1", "1.0.0", false},
		{"1.2.3", ">=1.0.0 <=1.2.3", true},
		{"1.2.4", ">=1.0.0 <=1.2.3", false},
		{"1.5.0", ">1.2.3 <1.6.0", true},
	}

	for _, tc := range testCases {
		got := db.IsVersionVulnerable(tc.version, tc.versionRange)
		if got != tc.want {
			t.Errorf("isVersionVulnerable(%s, %s) got %v want %v", tc.version, tc.versionRange, got, tc.want)
		}
	}
}

func assertEqualVulnerability(t testing.TB, got, want models.Vulnerability) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}
