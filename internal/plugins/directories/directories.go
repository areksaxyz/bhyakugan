package directories

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
)

type DirCheck struct {
	Path           string
	ExpectedString string // If empty, just check for 200 OK
}

var CommonPaths = []DirCheck{
	{".git/HEAD", "ref: refs/"},
	{".env", "="}, // Env files usually have key=value
	{"backup/", ""},
	{"admin/", ""},
	{"dashboard/", ""},
	{"config.php", ""},
	{"api/", ""},
	{"logs/", ""},
	{".svn/entries", "dir"}, // SVN usually starts with 'dir' or XML
	{".DS_Store", ""},
	// Web App Files
	{"phpinfo.php", "PHP Version"}, // Critical for LFI to RCE
	{"wp-login.php", "wp-submit"},
	{"wp-admin/", ""},
	{"robots.txt", "User-agent"},
	{"web.config", "<configuration>"},
	{".htaccess", ""},
	{"server-status", "Apache Status"},
	{"secrets", ""},
	{"credentials", ""},
	{"real_secret_dir/", ""}, // For testing Soft 404
}

// Scan checks for common hidden files and directories
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	// 0. Establish Soft 404 Baseline
	randPath := baseURL + "bhyakugan_baseline_test_404_" + fmt.Sprintf("%d", 123456)
	resp404, err404 := client.Get(randPath)
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

	seenLengths := make(map[int]int)
	if baselineLen > 0 {
		seenLengths[baselineLen] = 100 // Mark baseline as "seen often"
	}

	for _, check := range CommonPaths {
		target := baseURL + check.Path
		resp, err := client.Get(target)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		finalURL := resp.Request.URL.String()

		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)
			bodyLen := len(bodyStr)

			// --- ANTI-WAF / FALSE POSITIVE LOGIC ---
			wafSignatures := []string{"Request Rejected", "Support ID:", "Request Blocked", "web application firewall", "Incapsula", "incident ID"}
			isWafBlock := false
			for _, sig := range wafSignatures {
				if strings.Contains(bodyStr, sig) {
					isWafBlock = true
					break
				}
			}
			if isWafBlock { continue }

			// 1. Soft 404 Detection (Baseline Comparison)
			if baselineLen > 0 {
				// A. Redirect Check (Did we end up at the same place as the 404 page?)
				if baselineFinalURL != "" && finalURL == baselineFinalURL {
					continue
				}

				// B. Length Deviation Check (< 5% difference)
				diff := bodyLen - baselineLen
				if diff < 0 { diff = -diff }
				if diff < (baselineLen / 20) { // < 5% difference
					continue // Likely a soft 404
				}
				
				// C. Content Similarity Check
				if isSimilar(bodyStr, baselineBody) {
					continue
				}

				// D. Common Error Strings
				if strings.Contains(bodyStr, "Page Not Found") || strings.Contains(bodyStr, "404 Not Found") || strings.Contains(bodyStr, "Whoops, looks like something went wrong") {
					continue
				}
			}

			// 2. Redirect to Login Check
			// If we were redirected (target URL != final URL) and it looks like a login page
			if finalURL != target {
				lowerFinal := strings.ToLower(finalURL)
				if strings.Contains(lowerFinal, "login") || 
				   strings.Contains(lowerFinal, "signin") || 
				   strings.Contains(lowerFinal, "auth") || 
				   strings.Contains(lowerFinal, "account") ||
				   strings.Contains(lowerFinal, "session") {
					continue
				}
			}

			// 3. Detect mass redirects/generic pages by length (Fuzzy)
			isGeneric := false
			for seenLen := range seenLengths {
				// If length is within 10 bytes, it's likely the same page
				if bodyLen >= seenLen-10 && bodyLen <= seenLen+10 {
					seenLengths[seenLen]++
					if seenLengths[seenLen] > 3 { isGeneric = true }
					break
				}
			}
			if isGeneric { continue }
			seenLengths[bodyLen] = 1

			// 3. Detect WAF/Bot Challenges
			isChallenge := strings.Contains(bodyStr, "<script>") && (strings.Contains(bodyStr, "eval(") || len(bodyStr) > 5000)
			if strings.Contains(bodyStr, "ҺΏ") || strings.Contains(bodyStr, "σރ") { 
				isChallenge = true
			}

			found := false
			if !isChallenge {
				// FP Fix: HTML Content on "Non-HTML" paths is usually a Soft 404
				isHTML := strings.Contains(strings.ToLower(bodyStr), "<html") || strings.Contains(strings.ToLower(bodyStr), "<!doctype")
				
				// List of paths that SHOULD return HTML
				allowedHTML := map[string]bool{
					"phpinfo.php": true, 
					"server-status": true, 
					"wp-login.php": true, 
					"wp-admin/": true, 
					"dashboard/": true,
				}

				// If path is NOT expected to be HTML, but returns HTML, skip it (unless we look for a specific string later)
				if isHTML && !allowedHTML[check.Path] && check.ExpectedString == "" {
					continue // Likely Soft 404
				}

				// Even for allowed HTML, check for 404 text in Title
				if isHTML {
					title := ""
					if start := strings.Index(strings.ToLower(bodyStr), "<title>"); start != -1 {
						if end := strings.Index(strings.ToLower(bodyStr[start:]), "</title>"); end != -1 {
							title = bodyStr[start+7 : start+end]
						}
					}
					if strings.Contains(strings.ToLower(title), "page not found") || 
					   strings.Contains(strings.ToLower(title), "error") || 
					   strings.Contains(strings.ToLower(title), "404") {
						continue
					}
				}

				// Explicitly check specific files again if needed (like .env with HTML even if not caught above)
				if (check.Path == "config.php" || check.Path == ".env") && isHTML {
					continue
				}

				if check.ExpectedString != "" {
					if strings.Contains(bodyStr, check.ExpectedString) {
						found = true
						fmt.Printf("[+] FOUND Hidden Path: %s (Verified Content)\n", target)
					}
				} else {
					if bodyLen > 0 { 
						found = true
						fmt.Printf("[+] FOUND Hidden Path: %s (Status: 200)\n", target)
					}
				}
			}

			if found {
				onFound(core.Finding{
					Type:     "Hidden Directory",
					Target:   target,
					Detail:   fmt.Sprintf("Accessible Path (200 OK, Len: %d)", bodyLen),
					Severity: "Info",
				})
			}
		} 
		// Removed 403 reporting block to reduce noise. 
		// 403 is standard security behavior, not a finding.
	}
}

func stripHTML(s string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	return re.ReplaceAllString(s, " ")
}

// isSimilar calculates a simple token-based similarity ratio on TEXT content
func isSimilar(s1, s2 string) bool {
	t1 := stripHTML(s1)
	t2 := stripHTML(s2)

	if t1 == t2 { return true }
	
	// Tokenize by whitespace
	tokens1 := strings.Fields(t1)
	tokens2 := strings.Fields(t2)
	
	if len(tokens1) == 0 || len(tokens2) == 0 { return false }

	// Calculate Intersection (Jaccard-ish)
	set1 := make(map[string]bool)
	for _, t := range tokens1 { set1[t] = true }

	intersection := 0
	for _, t := range tokens2 {
		if set1[t] {
			intersection++
		}
	}

	maxLen := len(tokens1)
	if len(tokens2) > maxLen { maxLen = len(tokens2) }

	ratio := float64(intersection) / float64(maxLen)
	
	// If > 70% text tokens match, it's likely the same page (Soft 404)
	return ratio > 0.7
}

