package core

// Finding represents a vulnerability or interesting item found during the scan
type Finding struct {
	Type     string // e.g., "Secret", "Hidden Dir", "Vulnerability", "S3", "JS Analysis"
	Target   string // The URL or Host where it was found
	Detail   string // Specifics (e.g., the key itself, the path)
	Severity string // Critical, High, Medium, Low, Info
}
