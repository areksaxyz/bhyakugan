package wcd

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
)

var staticExtensions = []string{`.css`, `.js`, `.avif`, `.png`, `.jpg`, `.svg`}
var delimiters = []string{`/`, `;`, `?`, `#`, `%0a`}

// Scan tests for Web Cache Deception vulnerabilities
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}

	// 1. Get Base Response for comparison (e.g. from the root or a known dynamic path)
	// For simplicity, we compare extensions against the main page result
	baseResp, err := client.Get(baseURL)
	if err != nil {
		return
	}
	defer baseResp.Body.Close()
	baseBody, _ := io.ReadAll(baseResp.Body)
	baseBodyStr := string(baseBody)

	// If body is too short, WCD testing might not be reliable
	if len(baseBodyStr) < 50 {
		return
	}

	for _, ext := range staticExtensions {
		for _, delim := range delimiters {
			target := fmt.Sprintf("%s%stest%s", baseURL, delim, ext)
			
			resp, err := client.Get(target)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)

			// Heuristic Detection:
			// 1. Status is 200 OK
			// 2. Body matches the base dynamic page (reflection) - check similarity
			// 3. Cache headers are present AND HIT
			
			// Simple similarity check: Length difference within 20%
			diff := len(bodyStr) - len(baseBodyStr)
			if diff < 0 { diff = -diff }
			isReflected := len(bodyStr) > 0 && float64(diff) < float64(len(baseBodyStr))*0.2
			
			isHit := false
			cacheHeader := ""
			hitHeaders := []string{"X-Cache", "CF-Cache-Status", "X-Proxy-Cache", "X-Varnish", "CloudFront-Cache", "Akamai-Cache-Status"}
			
			for _, hh := range hitHeaders {
				val := strings.ToUpper(resp.Header.Get(hh))
				if strings.Contains(val, "HIT") {
					isHit = true
					cacheHeader = fmt.Sprintf("%s: %s", hh, val)
					break
				}
			}

			// STRICT WCD: ONLY REPORT IF HIT AND REFLECTED
			if resp.StatusCode == 200 && isReflected && isHit {
				// --- Stage 1: Sensitive Data Check ---
				lowerBody := strings.ToLower(bodyStr)
				hasSensitiveData := false
				if strings.Contains(lowerBody, "csrf") || 
				   strings.Contains(lowerBody, "xsrf") || 
				   strings.Contains(lowerBody, "token") || 
				   strings.Contains(lowerBody, "email") ||
				   strings.Contains(lowerBody, "user_id") ||
				   strings.Contains(lowerBody, "account") ||
				   strings.Contains(lowerBody, "session") ||
				   resp.Header.Get("Set-Cookie") != "" {
					hasSensitiveData = true
				}

				// --- Stage 2: Severity Gating ---
				severity := "Info"
				detail := fmt.Sprintf("Cache HIT observed on dynamic endpoint with static extension (%s).", cacheHeader)

				if hasSensitiveData {
					severity = "Medium" // Can go to High if manual verification proves user-specific data
					detail = fmt.Sprintf("POTENTIAL Web Cache Deception. Cache HIT observed with sensitive data (%s). Body contains CSRF/Token/Cookie/Email.", cacheHeader)
				} else {
					detail += " No obvious sensitive data found in body."
				}

				fmt.Printf("[!] WCD Match: %s [%s]\n", target, severity)
				onFound(core.Finding{
					Type:     "Web Cache Deception",
					Target:   target,
					Detail:   detail,
					Severity: severity,
				})
				return 
			}
		}
	}
}
