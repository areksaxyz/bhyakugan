package secrets

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/yupiyy/bhyakugan/internal/core"
)

// Validator defines how to check if a key is live
type Validator struct {
	Method          string
	URL             string // Use %s placeholder for the key
	Headers         map[string]string
	ExpectedCode    int
	ExpectedContent string // Substring to look for in success response
	BasicAuthUser   bool   // If true, use key as username in Basic Auth
}

type SecretPattern struct {
	Name      string
	Pattern   *regexp.Regexp
	Severity  string
	Validator *Validator 
}

var Patterns = []SecretPattern{
	{
		Name:     "OpenAI API Key",
		Pattern:  regexp.MustCompile(`sk-[a-zA-Z0-9]{48}|sk-proj-[a-zA-Z0-9-_]{48,}`),
		Severity: "Critical",
		Validator: &Validator{
			Method: "GET",
			URL:    "https://api.openai.com/v1/models",
			Headers: map[string]string{"Authorization": "Bearer %s"},
			ExpectedCode: 200,
		},
	},
	{
		Name:     "Anthropic API Key",
		Pattern:  regexp.MustCompile(`sk-ant-sid01-[a-zA-Z0-9-_]{93,}`),
		Severity: "Critical",
		Validator: &Validator{
			Method: "POST",
			URL:    "https://api.anthropic.com/v1/messages",
			Headers: map[string]string{
				"x-api-key":         "%s",
				"anthropic-version": "2023-06-01",
				"Content-Type":      "application/json",
			},
			ExpectedCode: 400, // 400 = Key valid but request bad. 401 = Invalid.
		},
	},
	{
		Name:     "HuggingFace Token",
		Pattern:  regexp.MustCompile(`hf_[a-zA-Z0-9]{34}`),
		Severity: "High",
		Validator: &Validator{
			Method: "GET",
			URL:    "https://huggingface.co/api/whoami-v2",
			Headers: map[string]string{"Authorization": "Bearer %s"},
			ExpectedCode: 200,
		},
	},
	{
		Name:     "AWS Access Key",
		Pattern:  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity: "Info", // Downgraded to Info (Unvalidated)
		Validator: nil,
	},
	{
		Name:     "Google API Key",
		Pattern:  regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		Severity: "Info",
		// Validation to distinguish Junk vs Real Key
		Validator: &Validator{
			Method: "GET",
			URL:    "https://www.googleapis.com/language/translate/v2?key=%s&q=hello&target=es", 
			ExpectedCode: 200, 
		},
	},
	{
		Name:     "Stripe Live Key",
		Pattern:  regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
		Severity: "Critical",
		Validator: &Validator{
			Method:        "GET",
			URL:           "https://api.stripe.com/v1/customers",
			BasicAuthUser: true,
			ExpectedCode:  200,
		},
	},
	{
		Name:     "Slack Bot Token",
		Pattern:  regexp.MustCompile(`xoxb-[0-9]{11,}-[0-9]{11,}-[0-9a-zA-Z]{24}`),
		Severity: "Critical",
		Validator: &Validator{
			Method: "POST",
			URL:    "https://slack.com/api/auth.test",
			Headers: map[string]string{"Authorization": "Bearer %s", "Content-Type": "application/json"},
			ExpectedCode:    200,
			ExpectedContent: "\"ok\":true",
		},
	},
	{
		Name:     "GitHub PAT",
		Pattern:  regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		Severity: "Critical",
		Validator: &Validator{
			Method: "GET",
			URL:    "https://api.github.com/user",
			Headers: map[string]string{"Authorization": "token %s"},
			ExpectedCode: 200,
		},
	},
	{
		Name:     "Heroku API Key",
		// Stricter Regex: Must be preceded by 'heroku'
		Pattern:  regexp.MustCompile(`(?i)(?:heroku).{0,20}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`), 
		Severity: "Medium",
		Validator: &Validator{
			Method: "POST",
			URL:    "https://api.heroku.com/apps",
			Headers: map[string]string{"Accept": "application/vnd.heroku+json; version=3", "Authorization": "Bearer %s"},
			ExpectedCode: 200,
		},
	},
	{
		Name:     "Private Key",
		Pattern:  regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |PGP )?PRIVATE KEY-----`),
		Severity: "High", // High (Unvalidated Credential)
		Validator: nil,
	},
	{
		Name:     "CodeIgniter DB Config",
		Pattern:  regexp.MustCompile(`'password'\s*=>\s*'[^']+'`),
		Severity: "Medium", // Default to Medium (Potential Config Leak)
		Validator: nil, 
		// Note: The pattern itself ensures a password assignment is present.
		// However, to be strict as requested:
		// If it matches, it means we found `'password' => '...'`.
		// We will treat this as HIGH in the detection logic if valid, but base definition starts lower to be safe.
	},
	{
		Name:     "SQL Dump (Plaintext Admin)",
		Pattern:  regexp.MustCompile(`(?i)INSERT\s+INTO.*(?:user|admin|account).*(?:VALUES|\().*`), 
		Severity: "Critical",
		Validator: nil,
	},
	{
		Name:     "SQL Dump (PII Data)",
		Pattern:  regexp.MustCompile(`(?i)INSERT\s+INTO.*(?:donatur|member|customer).*(?:VALUES|\().*`),
		Severity: "High",
		Validator: nil,
	},
	{
		Name:     "Database Backup File",
		Pattern:  regexp.MustCompile(`(?i)(?:db_|backup|dump).*\.sql`),
		Severity: "Info", 
		Validator: nil,
	},
}

// Additional helper for SQL content verification
func isSQLContent(content string) bool {
	upper := strings.ToUpper(content)
	// Check for SQL header signatures or common statements
	if strings.Contains(upper, "CREATE TABLE") || 
	   strings.Contains(upper, "INSERT INTO") || 
	   strings.Contains(upper, "MYSQLDUMP") || 
	   strings.Contains(upper, "-- MYSQL DUMP") ||
	   strings.Contains(upper, "SQLITE FORMAT") ||
	   strings.Contains(upper, "DROP TABLE") ||
	   strings.Contains(upper, "ALTER TABLE") {
		return true
	}
	return false
}

// Scan checks the response body for secrets
func Scan(url string, client *http.Client, onFound func(core.Finding)) {
	resp, err := client.Get(url)
	if err != nil { return }
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	DetectInContent(bodyStr, url, onFound)
}

func DetectInContent(content, sourceURL string, onFound func(core.Finding)) {
	for _, p := range Patterns {
		matches := p.Pattern.FindAllStringSubmatch(content, -1)
		seen := make(map[string]bool)
		for _, m := range matches {
			rawKey := m[0]
			if len(m) > 1 {
				rawKey = m[len(m)-1]
			}
			cleanKey := strings.Trim(rawKey, ` "'=`)
			
			// Ignore placeholders
			upperKey := strings.ToUpper(cleanKey)
			if strings.Contains(upperKey, "EXAMPLE") || strings.Contains(upperKey, "TEST") || strings.Contains(upperKey, "MOCK") {
				continue
			}

			if seen[cleanKey] { continue }
			seen[cleanKey] = true

			detail := fmt.Sprintf("Found %s pattern.", p.Name)
			severity := p.Severity

			// Special handling for Database Backup File:
			// If we matched the pattern (likely in the URL/Link), we MUST verify the content actually looks like SQL.
			// This prevents Soft 404s on .sql files from being reported.
			if p.Name == "Database Backup File" {
				// 1. If the match is just the filename in a directory listing or link, 
				// we usually scan the CONTENT of that file separately (via crawling).
				// But here `content` is the body of the page we are scanning.
				// If we are scanning `index.html` and it links to `backup.sql`, that's a finding (Info).
				// BUT if we are scanning `backup.sql` itself, we need to check content.
				
				// Case A: Pattern matched inside the body (Link Discovery) -> Info
				// Case B: We are scanning the file itself (sourceURL ends in .sql) -> Content Check
				
				if strings.HasSuffix(sourceURL, ".sql") {
					if !isSQLContent(content) {
						continue // False Positive (Soft 404 or non-SQL content)
					}
					severity = "Critical" // It's a verified dump!
					detail = "Verified SQL Dump file (Header/Structure confirmed)."
				} else {
					severity = "Info"
					detail = fmt.Sprintf("Potential Database Backup File reference: %s", cleanKey)
				}
			}
			
			// Special handling for CodeIgniter Config
			if p.Name == "CodeIgniter DB Config" {
				// The regex matches 'password' => '...', so we know it has a password candidate.
				// However, check if it's empty or placeholder
				if strings.Contains(cleanKey, "''") || strings.Contains(cleanKey, "'password'") { // empty password
					severity = "Medium"
					detail = "Found DB Config pattern (Empty/Placeholder password)."
				} else {
					severity = "High"
					detail = "Found DB Config with potential password assignment."
				}
			}

			if p.Validator != nil {
				// Special handling for localhost/test
				if strings.Contains(sourceURL, "localhost") && strings.Contains(p.Validator.URL, "localhost") {
					// Skip validation loop
				} else {
					status, msg := verifyKey(cleanKey, p.Validator)
					
					switch status {
					case "Valid":
						severity = "Critical"
						detail = fmt.Sprintf("VERIFIED %s: %s (%s)", p.Name, cleanKey, msg)
					case "Restricted":
						severity = "Info"
						detail = fmt.Sprintf("VERIFIED %s (Restricted): %s (%s)", p.Name, cleanKey, msg)
					case "Invalid":
						severity = "Info"
						detail = fmt.Sprintf("Invalid %s found (Verification Failed): %s", p.Name, msg)
					case "Error":
						// Report as Low/Info if verification failed due to network
						severity = "Low"
						detail = fmt.Sprintf("Potential %s (Verification Failed): %s. Err: %s", p.Name, cleanKey, msg)
					}
				}
			} else if severity == "High" {
				detail += " Validity not verified. No permission testing performed."
			}

			fmt.Printf("[+] SECRET MATCH: %s [%s]\n", p.Name, severity)
			onFound(core.Finding{
				Type:     "Secret Leak",
				Target:   sourceURL,
				Detail:   detail,
				Severity: severity,
			})
		}
	}
}

// status: Valid, Restricted, Invalid, Error
func verifyKey(key string, v *Validator) (string, string) {
	client := &http.Client{Timeout: 5 * time.Second}
	
targetURL := v.URL
	if strings.Contains(targetURL, "%s") {
		targetURL = fmt.Sprintf(targetURL, key)
	}

	req, err := http.NewRequest(v.Method, targetURL, nil)
	if err != nil { return "Error", err.Error() }

	for k, val := range v.Headers {
		if strings.Contains(val, "%s") {
			req.Header.Set(k, fmt.Sprintf(val, key))
		} else {
			req.Header.Set(k, val)
		}
	}

	if v.BasicAuthUser {
		req.SetBasicAuth(key, "")
	}

	resp, err := client.Do(req)
	if err != nil { return "Error", err.Error() }
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// 1. Check Success
	if resp.StatusCode == v.ExpectedCode {
		if v.ExpectedContent != "" {
			if !strings.Contains(bodyStr, v.ExpectedContent) {
				return "Invalid", "Content mismatch"
			}
		}
		
		// Additional Anti-FP: Check for Google/Standard denial keywords in body
		if strings.Contains(bodyStr, "REQUEST_DENIED") || strings.Contains(bodyStr, "API_KEY_INVALID") || strings.Contains(bodyStr, "key is invalid") {
			return "Invalid", "Denied by Provider"
		}

		return "Valid", "Active"
	}

	// 2. Check Restricted/Invalid
	if resp.StatusCode == 403 || resp.StatusCode == 401 {
		return "Restricted", "Unauthorized (Invalid or Restricted)"
	}

	// 3. Check Invalid (400, 401, 404 depending on API)
	// For most APIs, 401 = Invalid Key. 400 = Bad Request (Could be valid key but missing params).
	// Anthropic exception: 400 is "Valid Key but bad request".
	// Google exception: 400 is "Bad Request" (Key might be invalid OR valid). 
	// To be safe: If code is 4xx/5xx and NOT expected, assume Invalid OR Restricted.
	
	// Refined Logic:
	// If 400 -> "Invalid" for Google (usually INVALID_ARGUMENT or API_KEY_INVALID)
	// If 401 -> "Invalid"
	// If 5xx -> "Error"
	
	if resp.StatusCode == 401 {
		return "Invalid", "401 Unauthorized"
	}
	
	if resp.StatusCode >= 500 {
		return "Error", fmt.Sprintf("Server Error %d", resp.StatusCode)
	}

	return "Invalid", fmt.Sprintf("Status %d", resp.StatusCode)
}
