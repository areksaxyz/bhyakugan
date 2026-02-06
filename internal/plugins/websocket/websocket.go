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
	req, _ := http.NewRequest("GET", target, nil)
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
		fmt.Printf("[!] POSITIVE MATCH: CSWSH Vulnerability at %s\n", target)
		onFound(core.Finding{
			Type:     "Cross-Site WebSocket Hijacking",
			Target:   target,
			Detail:   "Server accepted WebSocket handshake from an unauthorized Origin (http://evil-bhyakugan.com).",
			Severity: "High",
		})
	} else if resp.StatusCode == 400 || resp.StatusCode == 426 {
		// 426 Upgrade Required or 400 might still indicate a WS endpoint exists
		// but our raw handshake was missing something.
		if strings.Contains(strings.ToLower(resp.Header.Get("Upgrade")), "websocket") {
			onFound(core.Finding{
				Type:     "WebSocket Endpoint",
				Target:   target,
				Detail:   "Potential WebSocket endpoint discovered.",
				Severity: "Info",
			})
		}
	}
}
