package ssti

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
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
}

func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	params := []string{"name", "id", "template", "view", "q"}
	for _, param := range params {
		for _, p := range SSTIPayloads {
			target := fmt.Sprintf("%s?%s=%s", baseURL, param, p.Payload)
			checkSSTI(target, p, client, onFound)
		}
	}
}

func checkSSTI(url string, p SSTIPayload, client *http.Client, onFound func(core.Finding)) {
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	// SMART CHECK: 
	// 1. Result must be in body
	// 2. Original payload must NOT be in body (to avoid reflection false positive)
	if strings.Contains(bodyStr, p.Check) && !strings.Contains(bodyStr, p.Payload) {
		fmt.Printf("[!] VALID SSTI MATCH: %s at %s\n", p.Name, url)
		onFound(core.Finding{
			Type:     "Server-Side Template Injection",
			Target:   url,
			Detail:   fmt.Sprintf("%s confirmed. Logic: %s", p.Name, p.Check),
			Severity: "Critical",
		})
	}
}