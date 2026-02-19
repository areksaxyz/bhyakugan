package directories

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/utils"
)

type DirCheck struct {
	Path           string
	ExpectedString string
}

var CommonPaths = []DirCheck{
	{".git/HEAD", "ref: refs/"},
	{".env", "="},
	{".env.old", "="},
	{".env.bak", "="},
	{".env.php", "return ["},
	{"backup/", ""},
	{"admin/", ""},
	{"dashboard/", ""},
	{"config.php", ""},
	{"api/", ""},
	{"logs/", ""},
	{".svn/entries", "dir"},
	{".DS_Store", ""},
	{"phpinfo.php", "PHP Version"},
	{"wp-login.php", "wp-submit"},
	{"wp-admin/", ""},
	{"robots.txt", "User-agent"},
	{"web.config", "<configuration>"},
	{".htaccess", ""},
	{"server-status", "Apache Status"},
	{"secrets", ""},
	{"credentials", ""},
	{"access.log", "GET /"},
	{"error.log", "stack trace"},
	{"logfile", ""},
	{"storage/logs/laravel.log", "stack trace"},
	{"wp-content/debug.log", "PHP Notice"},
	{"backup.zip", ""},
	{"data.zip", ""},
	{"sql.zip", ""},
	{"db.sql", "INSERT INTO"},
	{"database.sql", "INSERT INTO"},
	{"users.xlsx", ""},
	{".ssh/id_rsa", "PRIVATE KEY"},
	{"config/database.php", "return ["},
	{".aws/credentials", "aws_access_key"},
	{"node_modules/", ""},
	{"package.json", "\"dependencies\":"},
	{"package-lock.json", "\"lockfileVersion\""},
	{".npmrc", "_auth"},
	{"composer.json", "\"require\":"},
	{"Dockerfile", "FROM "},
	{"docker-compose.yml", "services:"},
	{".docker/config.json", "auths"},
}

func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	randPath := baseURL + "bhyakugan_baseline_test_404_" + fmt.Sprintf("%d", 123456)
	req404, _ := http.NewRequest("GET", randPath, nil)
	utils.SetDefaultHeaders(req404, randPath)
	resp404, err404 := client.Do(req404)

	var baselineLen int
	var baselineBody string
	var baselineFinalURL string

	if err404 == nil {
		body404, _ := io.ReadAll(resp404.Body)
		baselineBody = string(body404)
		baselineLen = len(baselineBody)
		baselineFinalURL = resp404.Request.URL.String()
		resp404.Body.Close()
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, check := range CommonPaths {
		wg.Add(1)
		go func(check DirCheck) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			target := baseURL + check.Path
			req, err := http.NewRequest("GET", target, nil)
			if err != nil {
				return
			}
			utils.SetDefaultHeaders(req, target)

			resp, err := client.Do(req)
			if err != nil {
				// TLS strict failed: verify with insecure fallback but mark as probable only.
				pathLower := strings.ToLower(check.Path)
				if utils.IsTLSError(err) && (strings.HasSuffix(pathLower, "web.config") || strings.HasSuffix(pathLower, ".htaccess")) {
					timeout := client.Timeout
					if timeout <= 0 {
						timeout = 10 * time.Second
					}
					status, insecureBody, _, insecureErr := utils.InsecureFetch(target, timeout)
					if insecureErr == nil && status == 200 {
						bodyLower := strings.ToLower(insecureBody)
						if (strings.HasSuffix(pathLower, "web.config") && isValidWebConfig(bodyLower)) ||
							(strings.HasSuffix(pathLower, ".htaccess") && isValidHtaccess(bodyLower)) {
							onFound(core.Finding{
								Type:       "Sensitive Config/Backup Exposed",
								Target:     target,
								Detail:     "Config file is readable only when TLS verification is disabled (certificate mismatch/validation error). Validate host ownership/scope before reporting.",
								Severity:   "High",
								Confidence: "probable",
							})
						}
					}
				}
				return
			}
			defer resp.Body.Close()

			finalURL := resp.Request.URL.String()
			if isAutodiscoverConfigRedirect(baseURL, check.Path, finalURL) {
				return
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				bodyStr := string(body)
				bodyLen := len(bodyStr)
				contentType := strings.ToLower(resp.Header.Get("Content-Type"))
				bodyLower := strings.ToLower(bodyStr)

				isHTML := strings.Contains(bodyLower, "<html") || strings.Contains(bodyLower, "<!doctype")
				hasSecret := hasStrongSecretEvidence(bodyLower)

				// --- ADVANCED ANTI-FP LOGIC ---

				// Rule A: Binary/Archives MUST NOT be HTML
				archiveExtensions := []string{".zip", ".7z", ".tar.gz", ".rar", ".sql", ".pdf", ".xlsx", ".csv"}
				for _, ext := range archiveExtensions {
					if strings.HasSuffix(strings.ToLower(check.Path), ext) && isHTML {
						return
					}
				}

				// Rule B: Sensitive files should NOT be HTML (unless they contain secrets)
				sensitiveExtensions := []string{".env", ".git/", ".svn/", ".bak", ".old", ".log", ".config", ".htaccess"}
				isSensitivePath := false
				for _, ext := range sensitiveExtensions {
					if strings.Contains(strings.ToLower(check.Path), ext) {
						isSensitivePath = true
						break
					}
				}

				if !hasSecret && isSensitivePath && (isHTML || strings.Contains(contentType, "html")) {
					return
				}

				// Rule C: Title-based 404 filtering
				if !hasSecret && isHTML {
					if strings.Contains(bodyLower, "<title>404") ||
						strings.Contains(bodyLower, "<title>not found") ||
						strings.Contains(bodyLower, "<title>error") ||
						strings.Contains(bodyLower, "<h1>page not found") {
						return
					}
				}

				// Rule D: Soft 404 Baseline Comparison (Smart Similarity)
				if !hasSecret && baselineLen > 0 && !strings.Contains(check.Path, "%00") {
					if baselineFinalURL != "" && finalURL == baselineFinalURL {
						return
					}

					// Compare using smart similarity (strips dynamic IDs)
					if isSimilar(bodyStr, baselineBody) {
						return
					}
				}

				found := false
				if strings.Contains(check.Path, "%00") {
					found = true
				} else {
					if check.ExpectedString != "" {
						if strings.Contains(bodyStr, check.ExpectedString) {
							found = true
						}
					} else {
						if bodyLen > 0 {
							found = true
						}
					}
				}

				if found {
					findingType := "Path Discovered"
					severity := "Info"
					confidence := "probable"
					detail := fmt.Sprintf("Accessible Path (200 OK, Len: %d)", bodyLen)

					// 1. Path-based classification (conservative)
					pathLower := strings.ToLower(check.Path)
					if strings.Contains(pathLower, ".htaccess") || strings.Contains(pathLower, "web.config") || strings.Contains(pathLower, "config.php") || strings.Contains(pathLower, ".bak") {
						severity = "High"
						findingType = "Sensitive Config/Backup Exposed"
					} else if strings.Contains(pathLower, "logs") || strings.Contains(pathLower, ".log") {
						severity = "Medium"
						findingType = "Log File Exposed"
					}

					// 2. Content-aware upgrade (requires evidence, not path name)
					if hasSecret {
						severity = "Critical"
						findingType = "Critical Data Leak in Path"
						confidence = "confirmed"
						detail = "Path contains extremely sensitive information (API Keys, Passwords, or Private Keys) in the response body."
					} else if strings.Contains(pathLower, ".sql") && isLikelySQLDump(bodyStr) {
						severity = "High"
						findingType = "Database Dump Exposed"
						confidence = "confirmed"
						detail = "SQL dump content confirmed from response body."
					} else if (strings.Contains(pathLower, ".env") || strings.Contains(pathLower, "credentials")) && hasConfigAssignments(bodyStr) {
						severity = "High"
						findingType = "Sensitive Config Exposed"
						confidence = "confirmed"
						detail = "Configuration-style key/value assignments found in response."
					} else if strings.Contains(bodyLower, "index of /") || strings.Contains(bodyLower, "parent directory") {
						if severity != "Critical" && severity != "High" {
							severity = "Medium"
							findingType = "Directory Listing Enabled"
						}
					}

					// High-confidence config exposure checks.
					if strings.HasSuffix(pathLower, "web.config") && isValidWebConfig(bodyLower) {
						findingType = "Sensitive Config/Backup Exposed"
						severity = "High"
						confidence = "confirmed"
						detail = "web.config content is directly readable and contains valid IIS/XML configuration directives."
					}
					if strings.HasSuffix(pathLower, ".htaccess") && isValidHtaccess(bodyLower) {
						findingType = "Sensitive Config/Backup Exposed"
						severity = "High"
						confidence = "confirmed"
						detail = ".htaccess content is directly readable and contains valid Apache directives."
					}

					if strings.Contains(check.Path, "%00") {
						findingType = "Null Byte Bypass"
						severity = "High"
						confidence = "confirmed"
						detail = fmt.Sprintf("Bypassed protection using Null Byte (%%00). Path: %s. Content Verified.", check.Path)
					}

					onFound(core.Finding{
						Type:       findingType,
						Target:     target,
						Detail:     detail,
						Severity:   severity,
						Confidence: confidence,
					})
				}
			}
		}(check)
	}
	wg.Wait()
}

func hasStrongSecretEvidence(bodyLower string) bool {
	indicators := []string{
		"aws_access_key_id",
		"aws_secret_access_key",
		"begin rsa private key",
		"begin ec private key",
		"begin openssh private key",
		"xoxb-",
		"sk_live_",
		"sk-proj-",
		"api_key=",
		"db_password=",
	}
	for _, s := range indicators {
		if strings.Contains(bodyLower, s) {
			return true
		}
	}
	return false
}

func hasConfigAssignments(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "password=") ||
		strings.Contains(lower, "db_password") ||
		strings.Contains(lower, "database_url") ||
		strings.Contains(lower, "api_key=") ||
		strings.Contains(lower, "secret_key")
}

func isLikelySQLDump(body string) bool {
	upper := strings.ToUpper(body)
	return strings.Contains(upper, "CREATE TABLE") ||
		strings.Contains(upper, "INSERT INTO") ||
		strings.Contains(upper, "-- MYSQL DUMP")
}

func isValidWebConfig(bodyLower string) bool {
	return strings.Contains(bodyLower, "<configuration") &&
		(strings.Contains(bodyLower, "<system.webserver") || strings.Contains(bodyLower, "<rewrite"))
}

func isValidHtaccess(bodyLower string) bool {
	indicators := []string{
		"rewriteengine",
		"rewriterule",
		"rewritecond",
		"options -indexes",
		"<files ",
		"deny from all",
		"authname",
		"authtype",
	}
	count := 0
	for _, s := range indicators {
		if strings.Contains(bodyLower, s) {
			count++
		}
	}
	return count >= 2
}

func isAutodiscoverConfigRedirect(baseURL, checkPath, finalURL string) bool {
	pathLower := strings.ToLower(checkPath)
	if !strings.HasSuffix(pathLower, "config.php") {
		return false
	}

	baseParsed, err := url.Parse(baseURL)
	if err != nil || baseParsed.Hostname() == "" {
		return false
	}

	finalParsed, err := url.Parse(finalURL)
	if err != nil || finalParsed.Hostname() == "" {
		return false
	}

	baseHost := strings.ToLower(baseParsed.Hostname())
	finalHost := strings.ToLower(finalParsed.Hostname())

	if baseHost == finalHost {
		return false
	}

	knownProviders := []string{
		"outlook.office365.com",
		"autodiscover.outlook.com",
		"outlook.com",
	}
	isKnownProvider := false
	for _, p := range knownProviders {
		if finalHost == p || strings.HasSuffix(finalHost, "."+p) {
			isKnownProvider = true
			break
		}
	}
	if !isKnownProvider {
		return false
	}

	q := strings.ToLower(finalParsed.RawQuery)
	return strings.Contains(q, "vd=autodiscover") || strings.Contains(q, "realm=")
}

func stripHTML(s string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	return re.ReplaceAllString(s, " ")
}

func stripDynamicContent(s string) string {
	// Remove numbers (IDs, timestamps) to defeat dynamic traps
	re := regexp.MustCompile(`[0-9]+`)
	return re.ReplaceAllString(s, "")
}

func isSimilar(s1, s2 string) bool {
	t1 := stripDynamicContent(stripHTML(s1))
	t2 := stripDynamicContent(stripHTML(s2))

	if t1 == t2 {
		return true
	}

	tokens1 := strings.Fields(t1)
	tokens2 := strings.Fields(t2)

	if len(tokens1) == 0 || len(tokens2) == 0 {
		return false
	}

	set1 := make(map[string]bool)
	for _, t := range tokens1 {
		set1[t] = true
	}

	intersection := 0
	for _, t := range tokens2 {
		if set1[t] {
			intersection++
		}
	}

	maxLen := len(tokens1)
	if len(tokens2) > maxLen {
		maxLen = len(tokens2)
	}

	ratio := float64(intersection) / float64(maxLen)
	return ratio > 0.7
}
