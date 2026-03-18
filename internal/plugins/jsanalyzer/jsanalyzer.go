package jsanalyzer

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/areksaxyz/bhyakugan/internal/core"
	"github.com/areksaxyz/bhyakugan/internal/payloadrepo"
	"github.com/areksaxyz/bhyakugan/internal/plugins/secrets"
	"github.com/areksaxyz/bhyakugan/internal/utils"
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
	tokenLeak = regexp.MustCompile(`(?i)(?:csrf|sessionid|phpsessid|jsessionid|aspsessionid|connect\.sid|sid|auth_token|access_token|refresh_token|api_key|secret_key|password|passwd|credentials)["']?\s*[:=]\s*["']([^"'\s]{8,})["']`)

	// Client-Side Token Generation (New: Yousef Elsheikh Report)
	cryptoJSLeak   = regexp.MustCompile(`CryptoJS\.(?:HmacSHA256|HmacSHA1|HmacMD5|AES\.encrypt)\s*\(`)
	secretConstant = regexp.MustCompile(`(?i)(?:var|const|let)\s+(\w*(?:token|secret|key|constant|auth|sign)\w*)\s*=\s*["']([^"']{4,})["']`)
	quotedLiteral  = regexp.MustCompile(`["']([^"'\\]{4,240})["']`)
)

const maxJSBody = 2 * 1024 * 1024

// ScanJS downloads and analyzes a JS file
func ScanJS(jsURL string, client *http.Client, wg *sync.WaitGroup, onFound func(core.Finding)) {
	if wg != nil {
		defer wg.Done()
	}

	emit := dedupeJSFindings(onFound)

	// PayPal-inspired XSSI Check (Alex Birsan)
	checkXSSI(jsURL, client, emit)

	resp, err := client.Get(jsURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, maxJSBody+1), maxJSBody+1))
	if err != nil {
		return
	}
	if len(bodyBytes) > maxJSBody {
		fmt.Printf("[*] Skipping oversized JS File: %s\n", jsURL)
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
	reqMap, errReqMap := http.NewRequest("GET", mapURL, nil)
	if errReqMap == nil {
		utils.SetDefaultHeaders(reqMap, mapURL)
		respMap, errMap := client.Do(reqMap)
		if errMap == nil {
			if respMap.StatusCode == 200 {
				severity := "Low"
				isLibrary := strings.Contains(jsURL, "jquery") ||
					strings.Contains(jsURL, "bootstrap") ||
					strings.Contains(jsURL, "node_modules") ||
					strings.Contains(jsURL, "vendor") ||
					strings.Contains(jsURL, "waves.min.js") ||
					strings.Contains(jsURL, "feather.min.js")

				if !isLibrary && (strings.Contains(jsURL, "app") ||
					strings.Contains(jsURL, "admin") ||
					strings.Contains(jsURL, "bundle") ||
					strings.Contains(jsURL, "main") ||
					strings.Contains(jsURL, "index")) {
					severity = "Medium"
				}

				fmt.Printf("[!] FOUND JS Sourcemap: %s [%s]\n", mapURL, severity)
				emit(core.Finding{
					Type:     "Recon: JS Sourcemap",
					Target:   mapURL,
					Detail:   "Javascript sourcemap file discovered. Can be used to recover original source code.",
					Severity: severity,
				})
			}
			respMap.Body.Close()
		}
	}

	// 1. Use centralized secrets detector
	secrets.DetectInContent(content, jsURL, emit)

	// 2. Check Endpoints
	checkRegexGroupAndProbe(content, apiEndpoint, "Full API Endpoint", jsURL, "Info", client, emit)
	checkRegexGroupAndProbe(content, apiPath, "API Path", jsURL, "Info", client, emit)
	checkRegexGroup(content, graphQL, "GraphQL-like Endpoint Detected", jsURL, "Info", emit)
	checkRegexGroup(content, adminPath, "Admin Path", jsURL, "Info", emit)
	emitKeywordReferenceFinding(content, jsURL, mergedJSEndpointKeywords(), "Recon: JS Keyword Surface", "Info", emit)

	// 3. Check Files
	checkRegexGroup(content, sensitiveFiles, "Sensitive File Ref", jsURL, "Low", emit)
	emitKeywordReferenceFinding(content, jsURL, mergedJSSecretKeywords(), "JS Sensitive Reference", "Medium", emit)

	// 4. Check for Token Leaks (XSSI candidates)
	checkRegexGroup(content, tokenLeak, "Leaked Token in JS", jsURL, "Medium", emit)

	// 5. Check for Client-Side Token Generation (New)
	if cryptoJSLeak.MatchString(content) {
		fmt.Printf("[!] HIGH: CryptoJS Usage with likely hardcoded secret in %s\n", jsURL)
		emit(core.Finding{
			Type:       "Client-Side Crypto Leak",
			Target:     jsURL,
			Detail:     "CryptoJS usage detected. Combined with hardcoded constants, this may allow attackers to generate valid authentication tokens.",
			Severity:   "High",
			Confidence: core.ConfidenceProbable,
		})
	}
	checkSecretConstants(content, jsURL, emit)
}

func mergedJSSecretKeywords() []string {
	return payloadrepo.LoadRepoLines(48,
		"verify/js-secret-keywords.txt",
		"js-secret-keywords.txt",
	)
}

func mergedJSEndpointKeywords() []string {
	return payloadrepo.LoadRepoLines(48,
		"verify/js-endpoint-keywords.txt",
		"js-endpoint-keywords.txt",
	)
}

func mergedInterestingResponseKeywords() []string {
	return payloadrepo.LoadRepoLines(48,
		"verify/response-interesting-keywords.txt",
		"response-interesting-keywords.txt",
	)
}

func findKeywordReferences(content string, keywords []string) ([]string, []string) {
	if len(keywords) == 0 || strings.TrimSpace(content) == "" {
		return nil, nil
	}

	refSeen := map[string]bool{}
	keywordSeen := map[string]bool{}
	var references []string
	var matchedKeywords []string
	for _, match := range quotedLiteral.FindAllStringSubmatch(content, -1) {
		if len(match) < 2 {
			continue
		}
		literal := strings.TrimSpace(match[1])
		if literal == "" {
			continue
		}
		lowerLiteral := strings.ToLower(literal)
		localHit := false
		for _, rawKeyword := range keywords {
			keyword := strings.ToLower(strings.TrimSpace(rawKeyword))
			if keyword == "" || !strings.Contains(lowerLiteral, keyword) {
				continue
			}
			localHit = true
			if !keywordSeen[keyword] {
				keywordSeen[keyword] = true
				matchedKeywords = append(matchedKeywords, keyword)
			}
		}
		if !localHit || refSeen[literal] {
			continue
		}
		refSeen[literal] = true
		references = append(references, literal)
		if len(references) >= 6 {
			break
		}
	}

	sort.Strings(matchedKeywords)
	return references, matchedKeywords
}

func emitKeywordReferenceFinding(content, source string, keywords []string, findingType, severity string, onFound func(core.Finding)) {
	references, matchedKeywords := findKeywordReferences(content, keywords)
	if len(references) == 0 {
		return
	}

	detail := fmt.Sprintf("Keyword-matched JS references found. Keywords: %s. Examples: %s", strings.Join(matchedKeywords, ", "), strings.Join(references, ", "))
	onFound(core.Finding{
		Type:       findingType,
		Target:     source,
		Detail:     detail,
		Severity:   severity,
		Confidence: core.ConfidenceProbable,
	})
}

func interestingResponseKeywordHits(content string) []string {
	keywords := mergedInterestingResponseKeywords()
	if len(keywords) == 0 || strings.TrimSpace(content) == "" {
		return nil
	}

	bodyLower := strings.ToLower(content)
	seen := map[string]bool{}
	var hits []string
	for _, rawKeyword := range keywords {
		keyword := strings.ToLower(strings.TrimSpace(rawKeyword))
		if keyword == "" || seen[keyword] || !strings.Contains(bodyLower, keyword) {
			continue
		}
		seen[keyword] = true
		hits = append(hits, keyword)
		if len(hits) >= 6 {
			break
		}
	}
	sort.Strings(hits)
	return hits
}

func dedupeJSFindings(onFound func(core.Finding)) func(core.Finding) {
	seen := make(map[string]bool)
	var mu sync.Mutex

	return func(f core.Finding) {
		key := strings.TrimSpace(f.Type) + "\n" + strings.TrimSpace(f.Target) + "\n" + strings.TrimSpace(f.Detail)
		mu.Lock()
		if seen[key] {
			mu.Unlock()
			return
		}
		seen[key] = true
		mu.Unlock()
		onFound(f)
	}
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
					Confidence: core.ConfidenceProbable,
				})
				seen[value] = true
			}
		}
	}
}

func checkXSSI(jsURL string, client *http.Client, onFound func(core.Finding)) {
	// 1. Request with standard client (might have cookies if set in previous requests)
	req1, err := http.NewRequest("GET", jsURL, nil)
	if err != nil {
		return
	}
	utils.SetDefaultHeaders(req1, jsURL)
	resp1, err1 := client.Do(req1)
	if err1 != nil {
		return
	}
	defer resp1.Body.Close()
	body1, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp1.Body, 5*1024*1024), 5*1024*1024))

	// 2. Request WITHOUT cookies (anonymous)
	req2, err := http.NewRequest("GET", jsURL, nil)
	if err != nil {
		return
	}
	utils.SetDefaultHeaders(req2, jsURL)

	// Create a temporary client with NO cookie jar for this request
	anonClient := &http.Client{Timeout: client.Timeout}
	resp2, err2 := anonClient.Do(req2)
	if err2 != nil {
		return
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp2.Body, 5*1024*1024), 5*1024*1024))

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
				Confidence: core.ConfidenceProbable,
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

func checkRegexGroupAndProbe(content string, re *regexp.Regexp, name, source, severity string, client *http.Client, onFound func(core.Finding)) {
	matches := re.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 {
			val := m[1]
			if len(val) < 4 || strings.Contains(val, "example.com") || strings.Contains(val, "node_modules") {
				continue
			}
			if !seen[val] {
				fmt.Printf("[+] [JS-Analyzer] FOUND and PROBING %s in %s: %s\n", name, source, val)

				onFound(core.Finding{
					Type:     "Recon: JS Endpoint",
					Target:   source,
					Detail:   fmt.Sprintf("%s: %s", name, val),
					Severity: severity,
				})

				// Probe the endpoint if it looks like an absolute path or full URL
				targetURL := val
				if strings.HasPrefix(val, "/") {
					// We need to resolve the relative path against the source URL
					parts := strings.Split(source, "/")
					if len(parts) >= 3 {
						targetURL = parts[0] + "//" + parts[2] + val
					}
				}

				if strings.HasPrefix(targetURL, "http") {
					probeEndpointMethods(targetURL, client, onFound)
				}
				seen[val] = true
			}
		}
	}
}

func probeEndpointMethods(url string, client *http.Client, onFound func(core.Finding)) {
	methods := []string{"GET", "POST", "PUT", "DELETE"}
	vulnerableMethods := []string{}

	// Create a client that doesn't follow redirects to avoid logging in
	noRedirectClient := &http.Client{
		Timeout:   client.Timeout,
		Transport: client.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, method := range methods {
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			continue
		}

		utils.SetDefaultHeaders(req, url)
		if method == "POST" || method == "PUT" {
			req.Header.Set("Content-Type", "application/json")
			// Add empty JSON body to avoid 400 Bad Request on some APIs
			req.Body = io.NopCloser(strings.NewReader("{}"))
		}

		resp, err := noRedirectClient.Do(req)
		if err != nil {
			continue
		}

		// If we get a 200 OK or 201 Created on an API endpoint without auth, it's highly suspicious
		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
			bodyStr := strings.ToLower(string(body))
			contentType := strings.ToLower(resp.Header.Get("Content-Type"))
			keywordHits := interestingResponseKeywordHits(string(body))

			// Filter out common false positives (e.g., standard login pages returning 200)
			if !strings.Contains(bodyStr, "<html") &&
				!strings.Contains(bodyStr, "login") &&
				len(bodyStr) > 0 &&
				(len(keywordHits) > 0 || strings.Contains(contentType, "json")) {
				if len(keywordHits) > 0 {
					vulnerableMethods = append(vulnerableMethods, fmt.Sprintf("%s (%d; keywords=%s)", method, resp.StatusCode, strings.Join(keywordHits, ",")))
				} else {
					vulnerableMethods = append(vulnerableMethods, fmt.Sprintf("%s (%d)", method, resp.StatusCode))
				}
			}
		}
		resp.Body.Close()
	}

	if len(vulnerableMethods) > 0 {
		onFound(core.Finding{
			Type:       "Unauthenticated API Access",
			Target:     url,
			Detail:     fmt.Sprintf("Endpoint discovered in JS allows unauthenticated access via methods: %s", strings.Join(vulnerableMethods, ", ")),
			Severity:   "High",
			Confidence: core.ConfidenceProbable,
		})
	}
}
