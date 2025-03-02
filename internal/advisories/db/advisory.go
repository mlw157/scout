package db

type Advisory struct {
	ID                  string `gorm:"column:id;primaryKey"`
	Package             string `gorm:"column:package"`
	VersionRange        string `gorm:"column:version_range"`
	FirstPatchedVersion string `gorm:"column:first_patched_version"`
	Ecosystem           string `gorm:"column:ecosystem"`
	Severity            string `gorm:"column:severity"`
	Summary             string `gorm:"column:summary"`
	Details             string `gorm:"column:details"`
	CVE                 string `gorm:"column:cve"`
	References          string `gorm:"column:references"`
}
