package detectors

import "regexp"

type FilePattern struct {
	Regex     *regexp.Regexp
	Ecosystem string
}

var (
	GoPattern       = FilePattern{Regex: regexp.MustCompile(`^go.mod$`), Ecosystem: "Go"}
	MavenPattern    = FilePattern{regexp.MustCompile(`^pom.xml$`), "Maven"}
	PipPattern      = FilePattern{regexp.MustCompile(`^requirements[-.0-9A-Za-z]*\.txt$`), "pip"}
	NpmPattern      = FilePattern{Regex: regexp.MustCompile(`^package-lock\.json$`), Ecosystem: "npm"}
	ComposerPattern = FilePattern{Regex: regexp.MustCompile(`^composer\.lock$`), Ecosystem: "Composer"}
)

var DefaultFilePatterns = []FilePattern{
	GoPattern, MavenPattern, PipPattern, NpmPattern, ComposerPattern,
}
