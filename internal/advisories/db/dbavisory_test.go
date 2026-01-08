package db_test

import (
	"reflect"
	"testing"

	"github.com/mlw157/scout/internal/advisories/db"
	"github.com/mlw157/scout/internal/models"
)

// todo tests (how to simulate db?)
func TestFetchVulnerabilities(t *testing.T) {

}

func TestGetDatabaseFile(t *testing.T) {
	testCases := []struct {
		name     string
		reviewed bool
		want     string
	}{
		{
			name:     "default database when reviewed is false",
			reviewed: false,
			want:     "scout.db",
		},
		{
			name:     "reviewed database when reviewed is true",
			reviewed: true,
			want:     "scout-reviewed.db",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := db.GetDatabaseFile(tc.reviewed)
			if got != tc.want {
				t.Errorf("GetDatabaseFile(%v) = %q, want %q", tc.reviewed, got, tc.want)
			}
		})
	}
}

func TestGetDatabaseURL(t *testing.T) {
	testCases := []struct {
		name     string
		reviewed bool
		wantEnd  string
	}{
		{
			name:     "default database URL",
			reviewed: false,
			wantEnd:  "/scout.db",
		},
		{
			name:     "reviewed database URL",
			reviewed: true,
			wantEnd:  "/scout-reviewed.db",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := db.GetDatabaseURL(tc.reviewed)
			if len(got) < len(tc.wantEnd) {
				t.Errorf("GetDatabaseURL(%v) = %q, too short", tc.reviewed, got)
				return
			}
			gotEnd := got[len(got)-len(tc.wantEnd):]
			if gotEnd != tc.wantEnd {
				t.Errorf("GetDatabaseURL(%v) ends with %q, want %q", tc.reviewed, gotEnd, tc.wantEnd)
			}
		})
	}
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
