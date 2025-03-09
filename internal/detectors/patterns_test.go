package detectors_test

import (
	"github.com/mlw157/scout/internal/detectors"
	"testing"
)

// todo regex tests
func TestPatterns(t *testing.T) {
	testCases := []struct {
		name     string
		pattern  detectors.FilePattern
		filename string
		want     bool
	}{
		// GoPattern
		{
			name:     "go.mod should match",
			pattern:  detectors.GoPattern,
			filename: "go.mod",
			want:     true,
		},
		{
			name:     "go.mod.test should not match",
			pattern:  detectors.GoPattern,
			filename: "go.mod.test",
			want:     false,
		},

		// PipPattern
		{
			name:     "requirements.txt should match",
			pattern:  detectors.PipPattern,
			filename: "requirements.txt",
			want:     true,
		},
		{
			name:     "requirements-dev.txt should match",
			pattern:  detectors.PipPattern,
			filename: "requirementsdev.txt",
			want:     true,
		},
		{
			name:     "requirements-2.9.txt should match",
			pattern:  detectors.PipPattern,
			filename: "requirements2.9.txt",
			want:     true,
		},
		{
			name:     "requirements.test should not match",
			pattern:  detectors.PipPattern,
			filename: "requirements.test",
			want:     false,
		},

		// MavenPattern
		{
			name:     "pom.xml should match",
			pattern:  detectors.MavenPattern,
			filename: "pom.xml",
			want:     true,
		},
		{
			name:     "pom.yaml should not match",
			pattern:  detectors.MavenPattern,
			filename: "pom.yaml",
			want:     false,
		},

		// ComposerPattern
		{
			name:     "composer.lock should match",
			pattern:  detectors.ComposerPattern,
			filename: "composer.lock",
			want:     true,
		},
		{
			name:     "composer.json should match",
			pattern:  detectors.ComposerPattern,
			filename: "composer.json",
			want:     true,
		},

		// NpmPattern
		{
			name:     "package-lock.json should match",
			pattern:  detectors.NpmPattern,
			filename: "package-lock.json",
			want:     true,
		},
		{
			name:     "package.json should match",
			pattern:  detectors.NpmPattern,
			filename: "package.json",
			want:     true,
		},

		{
			name:     "yarn.lock should match",
			pattern:  detectors.NpmPattern,
			filename: "yarn.lock",
			want:     true,
		},
	}

	for _, tc := range testCases {
		got := tc.pattern.Regex.MatchString(tc.filename)

		if got != tc.want {
			t.Errorf("Pattern %v with filename %v: got %v want %v", tc.pattern.Regex, tc.filename, got, tc.want)
		}
	}

}
