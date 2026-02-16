package typejuggling

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/utils"
)

type JugglingPayload struct {
	Name    string
	Payload string
}

var JugglingPayloads = []JugglingPayload{
	{"PHP Array Juggling (strcmp bypass)", "?user=admin&pass%5B%5D="},
	{"PHP Array Juggling (md5 bypass)", "?hash%5B%5D="},
	{"PHP Magic Hash (QNKCDZO)", "?pass=QNKCDZO"},
}

func Scan(baseURL string, client *http.Client, ctx core.ScanContext, onFound func(core.Finding)) {
	if ctx.Language != "php" && ctx.Language != "unknown" { return }

	lowerBase := strings.ToLower(baseURL)
	isAuthPath := strings.Contains(lowerBase, "login") || 
				  strings.Contains(lowerBase, "auth") || 
				  strings.Contains(lowerBase, "signin") || 
				  strings.Contains(lowerBase, "user") ||
				  strings.Contains(lowerBase, "session") ||
				  strings.Contains(lowerBase, "admin") ||
				  strings.Contains(lowerBase, "/vuln_")

	if !isAuthPath { return }

	reqBase, _ := http.NewRequest("GET", baseURL+"?bhyakugan_control=true", nil)
	utils.SetDefaultHeaders(reqBase, baseURL)
	baseResp, _ := client.Do(reqBase)
	
	baseLen := -1
	baseBodyStr := ""
	if baseResp != nil {
		headers := baseResp.Header
		if headers.Get("X-GitHub-Request-Id") != "" || 
		   strings.Contains(strings.ToLower(headers.Get("Server")), "github") ||
		   headers.Get("X-Runtime") != "" { 
			baseResp.Body.Close()
			return 
		}
		b, _ := io.ReadAll(baseResp.Body)
		baseBodyStr = strings.ToLower(string(b))
		baseLen = len(b)
		baseResp.Body.Close()
	}

	u, _ := url.Parse(baseURL)
	q := u.Query()
	authParams := []string{"pass", "password", "hash", "secret", "token"}
	testParams := make(map[string]string)
	
	if len(q) == 0 {
		for _, ap := range authParams { testParams[ap] = "1" }
	} else {
		for param := range q { testParams[param] = q.Get(param) }
	}

	for _, p := range JugglingPayloads {
		payloadQ, _ := url.ParseQuery(strings.TrimPrefix(p.Payload, "?"))
		
		for targetParam := range testParams {
			fuzzU, _ := url.Parse(baseURL)
			fuzzQ := fuzzU.Query()
			for k, v := range testParams { fuzzQ.Set(k, v) }
			for k, v := range payloadQ { fuzzQ.Set(k, v[0]) }
			
			fuzzU.RawQuery = fuzzQ.Encode()
			target := fuzzU.String()
			
			req, _ := http.NewRequest("GET", target, nil)
			utils.SetDefaultHeaders(req, target)
			resp, err := client.Do(req)
			if err != nil { continue }
			
			bodyBytes, _ := io.ReadAll(resp.Body)
			bodyStr := strings.ToLower(string(bodyBytes))
			bodyLen := len(bodyBytes)
			resp.Body.Close()

			if bodyLen == baseLen { continue }
			diff := bodyLen - baseLen
			if diff < 0 { diff = -diff }
			if diff < 50 { continue } 

			if strings.Contains(bodyStr, "incapsula") || strings.Contains(bodyStr, "request rejected") || strings.Contains(bodyStr, "firewall") { continue }

			success := false
			evidence := ""
			strongIndicators := []string{"logout", "session_id", "my account", "welcome,", "logged in as", "profile settings", "\"authenticated\":true"}
			for _, ind := range strongIndicators {
				if strings.Contains(bodyStr, ind) && !strings.Contains(baseBodyStr, ind) {
					success = true
					evidence = fmt.Sprintf("Bypass indicator found: '%s' in param '%s'", ind, targetParam)
					break
				}
			}

			if success {
				onFound(core.Finding{Type: "PHP Type Juggling", Target: target, Detail: fmt.Sprintf("%s detected. %s", p.Name, evidence), Severity: "High"})
				return
			}
		}
	}
}
