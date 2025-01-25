package detectors

import "regexp"

type FilePattern struct {
	Regex     *regexp.Regexp
	Ecosystem string
}

// patterns for dependency files of various ecosystems
var (
	GoPattern       = FilePattern{Regex: regexp.MustCompile(`^go.mod$`), Ecosystem: "go"}
	MavenPattern    = FilePattern{Regex: regexp.MustCompile(`^pom.xml$`), Ecosystem: "maven"}
	PipPattern      = FilePattern{Regex: regexp.MustCompile(`^requirements[-.0-9A-Za-z]*\.txt$`), Ecosystem: "pip"}
	NpmPattern      = FilePattern{Regex: regexp.MustCompile(`^package(-lock)?\.json$`), Ecosystem: "npm"}
	ComposerPattern = FilePattern{Regex: regexp.MustCompile(`^composer\.(lock|json)$`), Ecosystem: "composer"}
)

// DefaultFilePatterns map holds the file patterns indexed by ecosystem, ecosystem is essentially duplicated but helps a lot in matching files to ecosystems
var DefaultFilePatterns = map[string]FilePattern{
	"go":       GoPattern,
	"maven":    MavenPattern,
	"pip":      PipPattern,
	"npm":      NpmPattern,
	"composer": ComposerPattern,
}
