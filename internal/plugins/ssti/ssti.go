package ssti

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/utils"
)

type SSTIPayload struct {
	Name    string
	Payload string
	Check   string
}

// We use very unique large numbers to avoid common numbers appearing in timestamps/IDs
var SSTIPayloads = []SSTIPayload{
	{"SSTI Jinja2/Twig", "{{13377331*2}}", "26754662"},
	{"SSTI Smarty", "{13377331*2}", "26754662"},
	{"SSTI Freemarker", "${13377331*2}", "26754662"},
	{"SSTI Ruby ERB", "<%= 13377331 * 2 %>", "26754662"},
	{"SSTI Mako", "${13377331*2}", "26754662"},
	{"SSTI Velocity", "#set($x=13377331*2)$x", "26754662"},
}

func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	u, _ := url.Parse(baseURL)
	q := u.Query()

	// High probability params for SSTI
	sstiParams := []string{"template", "view", "name", "id", "q", "page", "redirect"}
	testParams := make(map[string]string)
	
	if len(q) == 0 {
		for _, sp := range sstiParams { testParams[sp] = "1" }
	} else {
		for param := range q { testParams[param] = q.Get(param) }
	}

	for _, p := range SSTIPayloads {
		for targetParam := range testParams {
			fuzzU, _ := url.Parse(baseURL)
			fuzzQ := fuzzU.Query()
			for k, v := range testParams { fuzzQ.Set(k, v) }
			fuzzQ.Set(targetParam, p.Payload)
			fuzzU.RawQuery = fuzzQ.Encode()
			target := fuzzU.String()

			req, _ := http.NewRequest("GET", target, nil)
			utils.SetDefaultHeaders(req, target)
			resp, err := client.Do(req)
			if err != nil { continue }
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(resp.Body)
			bodyStr := string(bodyBytes)

			// SMART CHECK: 
			// 1. Result must be in body
			// 2. Original payload must NOT be in body (to avoid reflection false positive)
			if strings.Contains(bodyStr, p.Check) && !strings.Contains(bodyStr, p.Payload) {
				onFound(core.Finding{
					Type:     "Server-Side Template Injection",
					Target:   target,
					Detail:   fmt.Sprintf("%s confirmed. Found output '%s' in param '%s'", p.Name, p.Check, targetParam),
					Severity: "Critical",
				})
				return // Found one, move to next host
			}
		}
	}
}
