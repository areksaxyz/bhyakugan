package graphql

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/utils"
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

// Scan checks for GraphQL endpoints and misconfigurations
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	var wg sync.WaitGroup

	// 1. Endpoint Discovery
	for _, path := range GraphQLEndpoints {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			target := baseURL + strings.TrimPrefix(p, "/")
			checkEndpoint(target, client, onFound)
		}(path)
	}

	wg.Wait()
}

func checkEndpoint(url string, client *http.Client, onFound func(core.Finding)) {
	// Step 1: TCP Connection & HTTP Request
	resp, err := client.Get(url)
	
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
	validContentType := strings.Contains(contentType, "application/json") || strings.Contains(contentType, "application/graphql")
	
	if !validContentType {
		// Exception: GraphiQL HTML interfaces
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if strings.Contains(strings.ToLower(bodyStr), "graphiql") || strings.Contains(strings.ToLower(bodyStr), "graphql playground") {
			// Valid GraphiQL Interface
			fmt.Printf("[+] FOUND GraphiQL Interface: %s\n", url)
			onFound(core.Finding{
				Type:     "GraphQL Interface",
				Target:   url,
				Detail:   "GraphiQL or Playground UI detected.",
				Severity: "Info",
			})
			// Probe Introspection/Batching even if it's UI
			checkIntrospection(url, client, onFound)
			checkBatching(url, client, onFound)
		}
		return
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// 3. Body Indicators (Strict)
	// Must contain one of: "errors", "data", "introspection", "Cannot query field", "syntax error"
	// BUT "errors" is too generic for JSON APIs. 
	// GraphQL errors usually look like: {"errors":[{"message":...}]}
	
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
			Type:     "GraphQL Endpoint",
			Target:   url,
			Detail:   "Valid GraphQL endpoint confirmed (JSON response with GraphQL structure).",
			Severity: "Info",
		})
		checkIntrospection(url, client, onFound)
		checkBatching(url, client, onFound)
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
	
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if strings.Contains(bodyStr, "__schema") && strings.Contains(bodyStr, "queryType") {
		fmt.Printf("[!] POSITIVE MATCH: GraphQL Introspection Enabled at %s\n", url)
		onFound(core.Finding{
			Type:     "GraphQL Introspection",
			Target:   url,
			Detail:   "Introspection Query Enabled (Schema Dump Possible)",
			Severity: "Medium", 
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
	
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// If response is an array [...] with multiple results, batching is enabled
	if strings.HasPrefix(strings.TrimSpace(bodyStr), "[") && strings.Contains(bodyStr, "__typename") {
		fmt.Printf("[!] POSITIVE MATCH: GraphQL Batching Enabled at %s\n", url)
		onFound(core.Finding{
			Type:     "GraphQL Batching",
			Target:   url,
			Detail:   "Batching Enabled (Potential Brute Force / DoS Amplification)",
			Severity: "Low",
		})
	}
}
