package secrets

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/areksaxyz/bhyakugan/internal/core"
	"github.com/areksaxyz/bhyakugan/internal/utils"
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
			Method:       "GET",
			URL:          "https://api.openai.com/v1/models",
			Headers:      map[string]string{"Authorization": "Bearer %s"},
			ExpectedCode: 200,
		},
	},
	{
		Name:     "Grok (xAI) API Key",
		Pattern:  regexp.MustCompile(`xai-[a-zA-Z0-9]{40,}`),
		Severity: "Critical",
		Validator: &Validator{
			Method:       "GET",
			URL:          "https://api.x.ai/v1/models",
			Headers:      map[string]string{"Authorization": "Bearer %s"},
			ExpectedCode: 200,
		},
	},
	{
		Name:     "DeepSeek API Key",
		Pattern:  regexp.MustCompile(`sk-[a-f0-9]{32}`),
		Severity: "Critical",
		Validator: &Validator{
			Method:       "GET",
			URL:          "https://api.deepseek.com/user/balance",
			Headers:      map[string]string{"Authorization": "Bearer %s"},
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
			Method:       "GET",
			URL:          "https://huggingface.co/api/whoami-v2",
			Headers:      map[string]string{"Authorization": "Bearer %s"},
			ExpectedCode: 200,
		},
	},
	{
		Name:      "AWS Access Key",
		Pattern:   regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
		Severity:  "Info",
		Validator: nil,
	},
	{
		Name: "AWS Secret Access Key",
		// Requiring a prefix or common assignment context to avoid entropy-only false positives
		Pattern:   regexp.MustCompile(`(?i)(?:aws_secret|aws_secret_access_key|secret_key|secret_access_key).{0,20}\b([0-9a-zA-Z/+=]{40})\b`),
		Severity:  "Info",
		Validator: nil,
	},
	{
		Name:      "Firebase Configuration",
		Pattern:   regexp.MustCompile(`(?is)(?:firebase|config).*?apiKey\s*[:=]\s*["'](AIza[0-9A-Za-z\-_]{35,})["']`),
		Severity:  "High",
		Validator: nil, // Note: The generic Google API Key validator in exploitation_engine.go handles Firebase installation abuse testing
	},
	{
		Name:     "Google API Key",
		Pattern:  regexp.MustCompile(`AIza[0-9A-Za-z\-_]+`),
		Severity: "Info",
		// Validation logic moved to exploitation_engine.go
		Validator: nil,
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
			Method:          "POST",
			URL:             "https://slack.com/api/auth.test",
			Headers:         map[string]string{"Authorization": "Bearer %s", "Content-Type": "application/json"},
			ExpectedCode:    200,
			ExpectedContent: `"ok":true`,
		},
	},
	{
		Name:     "GitHub PAT",
		Pattern:  regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		Severity: "Critical",
		Validator: &Validator{
			Method:       "GET",
			URL:          "https://api.github.com/user",
			Headers:      map[string]string{"Authorization": "token %s"},
			ExpectedCode: 200,
		},
	},
	{
		Name: "Heroku API Key",
		// Stricter Regex: Must be preceded by 'heroku'
		Pattern:  regexp.MustCompile(`(?i)(?:heroku).{0,20}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`),
		Severity: "Medium",
		Validator: &Validator{
			Method:       "POST",
			URL:          "https://api.heroku.com/apps",
			Headers:      map[string]string{"Accept": "application/vnd.heroku+json; version=3", "Authorization": "Bearer %s"},
			ExpectedCode: 200,
		},
	},
	{
		Name:      "Private Key",
		Pattern:   regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |PGP )?PRIVATE KEY-----\s*[A-Za-z0-9+/=\r\n]{64,}\s*-----END (?:RSA |EC |PGP )?PRIVATE KEY-----`),
		Severity:  "High", // High (Unvalidated Credential)
		Validator: nil,
	},
	{
		Name:      "CodeIgniter DB Config",
		Pattern:   regexp.MustCompile(`'password'\s*=>\s*'[^']+'`),
		Severity:  "Medium", // Default to Medium (Potential Config Leak)
		Validator: nil,
	},
	{
		Name:      "SQL Dump (Plaintext Admin)",
		Pattern:   regexp.MustCompile(`(?i)INSERT\s+INTO.*(?:user|admin|account).*(?:VALUES|\().*`),
		Severity:  "Critical",
		Validator: nil,
	},
	{
		Name:      "SQL Dump (PII Data)",
		Pattern:   regexp.MustCompile(`(?i)INSERT\s+INTO.*(?:donatur|member|customer).*(?:VALUES|\().*`),
		Severity:  "High",
		Validator: nil,
	},
	{
		Name:      "Database Backup File",
		Pattern:   regexp.MustCompile(`(?i)\b[a-z0-9._/-]{0,120}(?:backup|dump|db)[a-z0-9._/-]{0,120}\.sql\b`),
		Severity:  "Info",
		Validator: nil,
	},
	{
		Name:     "Generic Client ID",
		Pattern:  regexp.MustCompile(`(?i)(?:client_id|clientid|app_id|appid)\s*[:=]\s*["']([a-zA-Z0-9\-_]{16,})["']`),
		Severity: "Info",
	},
	{
		Name:     "Generic Client Secret",
		Pattern:  regexp.MustCompile(`(?i)(?:client_secret|clientsecret|app_secret|appsecret)\s*[:=]\s*["']([a-zA-Z0-9\-_]{32,})["']`),
		Severity: "High",
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
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
	bodyStr := string(body)

	DetectInContent(bodyStr, url, onFound)
}

func DetectInContent(content, sourceURL string, onFound func(core.Finding)) {
	type FoundKey struct {
		Name     string
		Key      string
		Severity string
		Pattern  SecretPattern
	}

	foundKeys := []FoundKey{}
	awsAccessKeys := []string{}
	awsSecretKeys := []string{}

	for _, p := range Patterns {
		matches := p.Pattern.FindAllStringSubmatch(content, -1)
		seen := make(map[string]bool)
		for _, m := range matches {
			rawKey := m[0]
			if len(m) > 1 {
				rawKey = m[len(m)-1]
			}
			cleanKey := strings.Trim(rawKey, ` "'=`)

			if len(cleanKey) < 8 && p.Name != "Database Backup File" {
				continue
			}
			if p.Name == "Google API Key" && len(cleanKey) < 35 {
				continue
			}

			if p.Name == "Private Key" && !isLikelyRealPrivateKeyBlock(cleanKey) {
				continue
			}

			// Ignore placeholders / documentation tokens
			upperKey := strings.ToUpper(cleanKey)
			if strings.Contains(upperKey, "EXAMPLE") ||
				strings.Contains(upperKey, "TEST") ||
				strings.Contains(upperKey, "MOCK") ||
				strings.Contains(upperKey, "YOUR_") ||
				strings.Contains(upperKey, "USERNAME") ||
				strings.Contains(upperKey, "PASSWORD") ||
				strings.Contains(upperKey, "TOKEN") ||
				strings.Contains(upperKey, "<") ||
				strings.Contains(upperKey, ">") {
				continue
			}

			if seen[cleanKey] {
				continue
			}
			seen[cleanKey] = true

			// Special handling for AWS Secret Access Key: Entropy check and Context Validation
			if p.Name == "AWS Secret Access Key" {
				entropy := utils.CalculateShannonEntropy(cleanKey)
				if entropy < 4.3 { // Stricter threshold for solo keys to avoid JS noise
					continue
				}

				// If no pair is found later, we want to know if 'aws' or 'key' keywords are nearby
				// We'll store the match index or just check context here
				if !hasContextKeywords(content, cleanKey, []string{"aws", "secret", "access", "key", "s3", "bucket", "config"}) {
					continue // Skip if no context found
				}

				awsSecretKeys = append(awsSecretKeys, cleanKey)
			}

			if p.Name == "AWS Access Key" {
				awsAccessKeys = append(awsAccessKeys, cleanKey)
			}

			foundKeys = append(foundKeys, FoundKey{
				Name:     p.Name,
				Key:      cleanKey,
				Severity: p.Severity,
				Pattern:  p,
			})
		}
	}

	// Pair Detection for AWS
	isAWSPairFound := len(awsAccessKeys) > 0 && len(awsSecretKeys) > 0
	if isAWSPairFound {
		onFound(core.Finding{
			Type:     "Secret Leak",
			Target:   sourceURL,
			Detail:   fmt.Sprintf("Found AWS Pair (Access Key ID and Secret Access Key) in the same content. This is a High Signal for Valid Credentials.\nAccess Key: %s\nSecret Key: [REDACTED]", awsAccessKeys[0]),
			Severity: "High",
		})
	}

	for _, fk := range foundKeys {
		p := fk.Pattern
		cleanKey := fk.Key
		severity := fk.Severity
		detail := fmt.Sprintf("Found %s pattern.", p.Name)

		// Special handling for Database Backup File:
		if p.Name == "Database Backup File" {
			if strings.HasSuffix(strings.ToLower(sourceURL), ".sql") {
				if !isSQLContent(content) {
					continue // False Positive (Soft 404 or non-SQL content)
				}
				severity = "Critical" // It's a verified dump!
				detail = "Verified SQL Dump file (Header/Structure confirmed)."
			} else {
				continue
			}
		}

		// Special handling for CodeIgniter Config
		if p.Name == "CodeIgniter DB Config" {
			if strings.Contains(cleanKey, "''") || strings.Contains(cleanKey, "'password'") { // empty password
				severity = "Medium"
				detail = "Found DB Config pattern (Empty/Placeholder password)."
			} else {
				severity = "High"
				detail = "Found DB Config with potential password assignment."
			}
		}

		if p.Name == "Google API Key" {
			RunExploitationEngine(p.Name, cleanKey, sourceURL, onFound)
			continue
		}

		// Don't duplicate if already flagged as AWS pair
		if isAWSPairFound && (p.Name == "AWS Access Key" || p.Name == "AWS Secret Access Key") {
			// Still might want to report them individually if they were found separately, but in the same content we already flagged the pair.
			// Let's report the Secret Key as Medium if part of a pair but not individually for now to avoid noise.
			if p.Name == "AWS Secret Access Key" {
				severity = "Medium"
				detail = fmt.Sprintf("AWS Secret Key part of a detected pair. Entropy: %.2f", utils.CalculateShannonEntropy(cleanKey))
			} else {
				continue // Skip individual Access Key report if pair found
			}
		} else if p.Name == "AWS Secret Access Key" {
			// Individual AWS Secret Key with no Access Key found in same content
			severity = "Low"
			detail = fmt.Sprintf("Found AWS Secret Access Key pattern (No matching Access Key found). Entropy: %.2f", utils.CalculateShannonEntropy(cleanKey))
		}

		if p.Validator != nil {
			if strings.Contains(sourceURL, "localhost") || strings.Contains(sourceURL, "127.0.0.1") {
				detail = fmt.Sprintf("Found %s pattern (Validation skipped on localhost).", p.Name)
				// Keep severity as defined in pattern
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
					continue
				case "Error":
					continue
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

func hasContextKeywords(content, key string, keywords []string) bool {
	idx := strings.Index(content, key)
	if idx == -1 {
		return false
	}

	start := idx - 100
	if start < 0 {
		start = 0
	}
	end := idx + len(key) + 100
	if end > len(content) {
		end = len(content)
	}

	context := strings.ToLower(content[start:end])
	for _, kw := range keywords {
		if strings.Contains(context, kw) {
			return true
		}
	}
	return false
}

func isLikelyRealPrivateKeyBlock(block string) bool {
	if strings.Contains(block, `replace("-----BEGIN PRIVATE KEY-----"`) ||
		strings.Contains(block, `replace("-----END PRIVATE KEY-----"`) ||
		strings.Contains(block, `REPLACE("-----BEGIN PRIVATE KEY-----"`) ||
		strings.Contains(block, `REPLACE("-----END PRIVATE KEY-----"`) {
		return false
	}

	re := regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |PGP )?PRIVATE KEY-----\s*([A-Za-z0-9+/=\r\n]+)\s*-----END (?:RSA |EC |PGP )?PRIVATE KEY-----`)
	m := re.FindStringSubmatch(block)
	if len(m) < 2 {
		return false
	}

	payload := strings.TrimSpace(m[1])
	if payload == "" {
		return false
	}
	if strings.ContainsAny(payload, `"'\{\}\[\],;`) {
		return false
	}

	compact := strings.ReplaceAll(strings.ReplaceAll(payload, "\n", ""), "\r", "")
	if len(compact) < 128 {
		return false
	}

	return strings.Count(payload, "\n") >= 2
}

// status: Valid, Restricted, Invalid, Error
func verifyKey(key string, v *Validator) (string, string) {
	client := &http.Client{Timeout: 5 * time.Second}

	targetURL := v.URL
	if strings.Contains(targetURL, "%s") {
		targetURL = fmt.Sprintf(targetURL, key)
	}

	req, err := http.NewRequest(v.Method, targetURL, nil)
	if err != nil {
		return "Error", err.Error()
	}

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
	if err != nil {
		return "Error", err.Error()
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
	bodyStr := string(body)

	if resp.StatusCode == v.ExpectedCode {
		if v.ExpectedContent != "" {
			if !strings.Contains(bodyStr, v.ExpectedContent) {
				return "Invalid", "Content mismatch"
			}
		}

		if strings.Contains(bodyStr, "REQUEST_DENIED") || strings.Contains(bodyStr, "API_KEY_INVALID") || strings.Contains(bodyStr, "key is invalid") {
			return "Invalid", "Denied by Provider"
		}

		return "Valid", "Active"
	}

	if resp.StatusCode == 403 || resp.StatusCode == 401 {
		return "Restricted", "Unauthorized (Invalid or Restricted)"
	}

	if resp.StatusCode == 401 {
		return "Invalid", "401 Unauthorized"
	}

	if resp.StatusCode >= 500 {
		return "Error", fmt.Sprintf("Server Error %d", resp.StatusCode)
	}

	return "Invalid", fmt.Sprintf("Status %d", resp.StatusCode)
}
