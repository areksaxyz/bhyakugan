package websocket

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/yupiyy/bhyakugan/internal/core"
)

var WSEndpoints = []string{
	"/ws",
	"/websocket",
	"/socket.io/",
	"/chat",
	"/realtime",
	"/api/v1/ws",
	"/cable", // Rails ActionCable
}

// Scan tests for WebSocket vulnerabilities
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	var wg sync.WaitGroup

	for _, path := range WSEndpoints {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			target := baseURL + strings.TrimPrefix(p, "/")
			checkHandshake(target, client, onFound)
		}(path)
	}

	wg.Wait()
}

func checkHandshake(target string, client *http.Client, onFound func(core.Finding)) {
	// 1. Try a standard WebSocket Handshake
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	// Use an external origin to test CSWSH
	req.Header.Set("Origin", "http://evil-bhyakugan.com")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// 101 Switching Protocols means the handshake was successful
	if resp.StatusCode == 101 {
		fmt.Printf("[!] POSITIVE MATCH: CSWSH signal at %s\n", target)
		severity := "Info"
		detail := "Server accepted cross-origin WebSocket handshake (Origin=http://evil-bhyakugan.com). This is policy misconfiguration signal only; no authenticated action, cookie replay, or CSRF-over-WebSocket proof was observed."
		if hasSessionLikeCookie(resp.Header.Values("Set-Cookie")) {
			severity = "Low"
			detail += " Session-like cookie observed in handshake response, but session-auth-confirmed is not proven."
		}
		onFound(core.Finding{
			Type:       "Cross-Site WebSocket Hijacking",
			Target:     target,
			Detail:     detail,
			Severity:   severity,
			Confidence: "probable",
		})
	} else if resp.StatusCode == 400 || resp.StatusCode == 426 {
		// 426 Upgrade Required or 400 might still indicate a WS endpoint exists
		// but our raw handshake was missing something.
		if strings.Contains(strings.ToLower(resp.Header.Get("Upgrade")), "websocket") {
			onFound(core.Finding{
				Type:       "WebSocket Endpoint",
				Target:     target,
				Detail:     "Potential WebSocket endpoint discovered.",
				Severity:   "Info",
				Confidence: "probable",
			})
		}
	}
}

func hasSessionLikeCookie(cookies []string) bool {
	for _, c := range cookies {
		cl := strings.ToLower(c)
		if strings.Contains(cl, "session") ||
			strings.Contains(cl, "auth") ||
			strings.Contains(cl, "token") ||
			strings.Contains(cl, "jwt") {
			return true
		}
	}
	return false
}
