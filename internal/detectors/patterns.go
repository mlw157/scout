package detectors

import "regexp"

type FilePattern struct {
	Regex     *regexp.Regexp
	Ecosystem string
}

var DefaultFilePatterns = []FilePattern{
	{regexp.MustCompile(`^go.mod$`), "Go"},
	{regexp.MustCompile(`^pom.xml$`), "Maven"},
	{regexp.MustCompile(`^requirements\.txt$`), "pip"},
}
