package core

// Finding represents a vulnerability or interesting item found during the scan
type Finding struct {
	Type     string // e.g., "Secret", "Hidden Dir", "Vulnerability", "S3", "JS Analysis"
	Target   string // The URL or Host where it was found
	Detail   string // Specifics (e.g., the key itself, the path)
	Severity string // Critical, High, Medium, Low, Info
	Confidence string // confirmed, probable, noisy
}

// ScanContext holds intelligence about the current target
type ScanContext struct {
	Language  string // php, node, python, java, dotnet, unknown
	Framework string // laravel, django, express, spring, etc.
	WAF       string // cloudflare, akamai, imperva, etc.
	Baseline  int    // baseline response length
}
