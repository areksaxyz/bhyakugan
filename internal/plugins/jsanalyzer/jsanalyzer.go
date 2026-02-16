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
	apiEndpoint   = regexp.MustCompile(`"((?:https?:)?//[^"']+/api/[a-zA-Z0-9/_-]+)"`) 
	apiPath       = regexp.MustCompile(`"(/api/v?\d*/[a-zA-Z0-9/_-]{2,})"`) 
	graphQL       = regexp.MustCompile(`"(/graphql[a-zA-Z0-9/_-]*)"`) 
	adminPath     = regexp.MustCompile(`"(/admin[a-zA-Z0-9/_-]*)"`) 

	// Sensitive Files
	sensitiveFiles = regexp.MustCompile(`"([a-zA-Z0-9_/.-]+\.(?:sql|env|bak|config|xml|json|pem|key))"`)
)

// ScanJS downloads and analyzes a JS file
func ScanJS(jsURL string, client *http.Client, wg *sync.WaitGroup, onFound func(core.Finding)) {
	defer wg.Done()

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