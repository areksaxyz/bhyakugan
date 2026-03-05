package jsanalyzer

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/plugins/secrets"
	"github.com/yupiyy/bhyakugan/internal/utils"
)

var (
	// API Endpoints
	apiEndpoint = regexp.MustCompile(`"((?:https?:)?//[^"']+/api/[a-zA-Z0-9/_-]+)"`)
	apiPath     = regexp.MustCompile(`"(/api/v?\d*/[a-zA-Z0-9/_-]{2,})"`)
	graphQL     = regexp.MustCompile(`"(/graphql[a-zA-Z0-9/_-]*)"`)
	adminPath   = regexp.MustCompile(`"(/admin[a-zA-Z0-9/_-]*)"`)

	// Sensitive Files
	sensitiveFiles = regexp.MustCompile(`"([a-zA-Z0-9_/.-]+\.(?:sql|env|bak|config|xml|json|pem|key))"`)

	// XSSI / Sensitive Tokens
	tokenLeak = regexp.MustCompile(`(?i)(?:csrf|sessionid|auth_token|access_token|refresh_token|api_key|secret_key|password|passwd|credentials)["']?\s*[:=]\s*["']([^"'\s]{8,})["']`)

	// Client-Side Token Generation (New: Yousef Elsheikh Report)
	cryptoJSLeak   = regexp.MustCompile(`CryptoJS\.(?:HmacSHA256|HmacSHA1|HmacMD5|AES\.encrypt)\s*\(`)
	secretConstant = regexp.MustCompile(`(?i)(?:var|const|let)\s+(\w*(?:token|secret|key|constant|auth|sign)\w*)\s*=\s*["']([^"']{4,})["']`)
)

// ScanJS downloads and analyzes a JS file
func ScanJS(jsURL string, client *http.Client, wg *sync.WaitGroup, onFound func(core.Finding)) {
	if wg != nil {
		defer wg.Done()
	}

	// PayPal-inspired XSSI Check (Alex Birsan)
	checkXSSI(jsURL, client, onFound)

	resp, err := client.Get(jsURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	content := string(bodyBytes)

	// Filter Noise
	if len(content) < 50 || strings.Contains(jsURL, "jquery") || strings.Contains(jsURL, "bootstrap") {
		return
	}

	fmt.Printf("[*] Analyzing JS File: %s\n", jsURL)

	// 0. Check for Sourcemaps (.map)
	mapURL := jsURL + ".map"
	reqMap, _ := http.NewRequest("GET", mapURL, nil)
	utils.SetDefaultHeaders(reqMap, mapURL)
	respMap, errMap := client.Do(reqMap)
	if errMap == nil {
		if respMap.StatusCode == 200 {
			fmt.Printf("[!] FOUND JS Sourcemap: %s\n", mapURL)
			onFound(core.Finding{
				Type:     "Recon: JS Sourcemap",
				Target:   mapURL,
				Detail:   "Javascript sourcemap file discovered. Can be used to recover original source code.",
				Severity: "Low",
			})
		}
		respMap.Body.Close()
	}

	// 1. Use centralized secrets detector
	secrets.DetectInContent(content, jsURL, onFound)

	// 2. Check Endpoints
	checkRegexGroup(content, apiEndpoint, "Full API Endpoint", jsURL, "Info", onFound)
	checkRegexGroup(content, apiPath, "API Path", jsURL, "Info", onFound)
	checkRegexGroup(content, graphQL, "GraphQL-like Endpoint Detected", jsURL, "Info", onFound)
	checkRegexGroup(content, adminPath, "Admin Path", jsURL, "Info", onFound)

	// 3. Check Files
	checkRegexGroup(content, sensitiveFiles, "Sensitive File Ref", jsURL, "Low", onFound)

	// 4. Check for Token Leaks (XSSI candidates)
	checkRegexGroup(content, tokenLeak, "Leaked Token in JS", jsURL, "Medium", onFound)

	// 5. Check for Client-Side Token Generation (New)
	if cryptoJSLeak.MatchString(content) {
		fmt.Printf("[!] HIGH: CryptoJS Usage with likely hardcoded secret in %s\n", jsURL)
		onFound(core.Finding{
			Type:       "Client-Side Crypto Leak",
			Target:     jsURL,
			Detail:     "CryptoJS usage detected. Combined with hardcoded constants, this may allow attackers to generate valid authentication tokens.",
			Severity:   "High",
			Confidence: "probable",
		})
	}
	checkSecretConstants(content, jsURL, onFound)
}

func checkSecretConstants(content, source string, onFound func(core.Finding)) {
	matches := secretConstant.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 2 {
			varName := m[1]
			value := m[2]

			// Filter out junk
			if len(value) < 6 || strings.Contains(strings.ToLower(value), "test") || strings.Contains(strings.ToLower(value), "dummy") {
				continue
			}

			if !seen[value] {
				fmt.Printf("[+] [JS-Analyzer] FOUND Potential Secret Constant: %s = %s\n", varName, value)
				onFound(core.Finding{
					Type:       "Secret Constant Leak",
					Target:     source,
					Detail:     fmt.Sprintf("Potential hardcoded secret or token generator constant: %s = %s", varName, value),
					Severity:   "Medium",
					Confidence: "probable",
				})
				seen[value] = true
			}
		}
	}
}

func checkXSSI(jsURL string, client *http.Client, onFound func(core.Finding)) {
	// 1. Request with standard client (might have cookies if set in previous requests)
	req1, _ := http.NewRequest("GET", jsURL, nil)
	utils.SetDefaultHeaders(req1, jsURL)
	resp1, err1 := client.Do(req1)
	if err1 != nil {
		return
	}
	defer resp1.Body.Close()
	body1, _ := io.ReadAll(resp1.Body)

	// 2. Request WITHOUT cookies (anonymous)
	req2, _ := http.NewRequest("GET", jsURL, nil)
	utils.SetDefaultHeaders(req2, jsURL)

	// Create a temporary client with NO cookie jar for this request
	anonClient := &http.Client{Timeout: client.Timeout}
	resp2, err2 := anonClient.Do(req2)
	if err2 != nil {
		return
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)

	// If body length is significantly different OR content changes, it might be dynamic JS
	if len(body1) != len(body2) && len(body1) > 0 && len(body2) > 0 {
		// Further analysis: look for tokens in body1
		if tokenLeak.Match(body1) {
			fmt.Printf("[!] POTENTIAL XSSI: Dynamic JS content detected at %s\n", jsURL)
			onFound(core.Finding{
				Type:       "Cross-Site Script Inclusion (XSSI)",
				Target:     jsURL,
				Detail:     "JS file content changes based on authentication state and contains sensitive-looking tokens. Attackers can include this script cross-origin to steal data.",
				Severity:   "High",
				Confidence: "probable",
			})
		}
	}
}

func checkRegexGroup(content string, re *regexp.Regexp, name, source, severity string, onFound func(core.Finding)) {
	matches := re.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 {
			val := m[1]
			// Filter noise
			if len(val) < 4 ||
				strings.Contains(val, "example.com") ||
				strings.Contains(val, "w3.org") ||
				strings.Contains(val, "manifest.json") ||
				strings.Contains(val, "package.json") ||
				strings.Contains(val, "opensearch.xml") ||
				strings.Contains(val, "opensearch-gist.xml") ||
				strings.Contains(val, "node_modules") {
				continue
			}
			if !seen[val] {
				fmt.Printf("[+] [JS-Analyzer] FOUND %s in %s: %s\n", name, source, val)

				detail := fmt.Sprintf("%s: %s", name, val)
				if name == "GraphQL-like Endpoint Detected" {
					detail += " (No introspection / query execution observed)"
				}

				onFound(core.Finding{
					Type:     "Recon: JS Endpoint",
					Target:   source,
					Detail:   detail,
					Severity: severity,
				})
				seen[val] = true
			}
		}
	}
}
