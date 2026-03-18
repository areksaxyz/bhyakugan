package wcd

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/areksaxyz/bhyakugan/internal/core"
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
	baseBody, _ := io.ReadAll(io.LimitReader(io.LimitReader(baseResp.Body, 5*1024*1024), 5*1024*1024))
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

			body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
			bodyStr := string(body)

			// Heuristic Detection:
			// 1. Status is 200 OK
			// 2. Body matches the base dynamic page (reflection) - check similarity
			// 3. Cache headers are present AND HIT

			// Simple similarity check: Length difference within 20%
			diff := len(bodyStr) - len(baseBodyStr)
			if diff < 0 {
				diff = -diff
			}
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
				// --- Stage 1: Sensitive Data Check (strict)
				lowerBody := strings.ToLower(bodyStr)
				hasSensitiveData := strings.Contains(lowerBody, "csrf_token") ||
					strings.Contains(lowerBody, "xsrf-token") ||
					strings.Contains(lowerBody, "sessionid=") ||
					strings.Contains(lowerBody, "auth_token") ||
					strings.Contains(lowerBody, "jwt")
				hasSetCookie := resp.Header.Get("Set-Cookie") != ""

				// Only report when potential user-specific sensitive cache is observed.
				if !(hasSensitiveData && hasSetCookie) {
					continue
				}

				severity := "Medium"
				detail := fmt.Sprintf("POTENTIAL Web Cache Deception. Cache HIT with sensitive markers and Set-Cookie (%s).", cacheHeader)

				fmt.Printf("[!] WCD Match: %s [%s]\n", target, severity)
				onFound(core.Finding{
					Type:       "Web Cache Deception",
					Target:     target,
					Detail:     detail,
					Severity:   severity,
					Confidence: core.ConfidenceProbable,
				})
				return
			}
		}
	}
}
