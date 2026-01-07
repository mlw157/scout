package detectors

import "regexp"

type FilePattern struct {
	Regex     *regexp.Regexp
	Ecosystem string
}

// patterns for dependency files of various ecosystems
var (
	RubyPattern     = FilePattern{Regex: regexp.MustCompile(`^Gemfile\.lock$`), Ecosystem: "gem"}
	RustPattern     = FilePattern{Regex: regexp.MustCompile(`^Cargo\.lock$`), Ecosystem: "crates.io"}
	GoPattern       = FilePattern{Regex: regexp.MustCompile(`^go.mod$`), Ecosystem: "Go"}
	MavenPattern    = FilePattern{Regex: regexp.MustCompile(`^pom.xml$`), Ecosystem: "maven"}
	PipPattern      = FilePattern{Regex: regexp.MustCompile(`^(requirements[-.0-9A-Za-z]*\.txt|poetry\.lock)$`), Ecosystem: "pip"}
	NpmPattern      = FilePattern{Regex: regexp.MustCompile(`^(package(-lock)?\.json|yarn\.lock)$`), Ecosystem: "npm"}
	ComposerPattern = FilePattern{Regex: regexp.MustCompile(`^composer\.(lock|json)$`), Ecosystem: "composer"}
)

// DefaultFilePatterns map holds the file patterns indexed by ecosystem, ecosystem is essentially duplicated but helps a lot in matching files to ecosystems
var DefaultFilePatterns = map[string]FilePattern{
	"gem":       RubyPattern,
	"crates.io": RustPattern,
	"Go":        GoPattern,
	"maven":     MavenPattern,
	"pip":       PipPattern,
	"npm":       NpmPattern,
	"composer":  ComposerPattern,
}
