package ssti

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/payloadrepo"
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
	{"SSTI Jinja2/Twig (String Mult)", "{{'7'*7}}", "7777777"},
	{"SSTI Smarty", "{13377331*2}", "26754662"},
	{"SSTI Freemarker", "${13377331*2}", "26754662"},
	{"SSTI Freemarker (Alt)", "${131*7}", "917"},
	{"SSTI Ruby ERB", "<%= 13377331 * 2 %>", "26754662"},
	{"SSTI Mako", "${13377331*2}", "26754662"},
	{"SSTI Velocity", "#set($x=13377331*2)$x", "26754662"},
}

func deriveExpectedFromPayload(payload string) (string, bool) {
	p := strings.ReplaceAll(strings.ToLower(payload), " ", "")
	switch {
	case strings.Contains(p, "13377331*2"):
		return "26754662", true
	case strings.Contains(p, "'7'*7"):
		return "7777777", true
	case strings.Contains(p, "131*7"):
		return "917", true
	default:
		return "", false
	}
}

func loadPATTTArithmeticPayloads() []SSTIPayload {
	lines := payloadrepo.LoadLines("Server Side Template Injection/Intruder/ssti.fuzz", 180)
	if len(lines) == 0 {
		return nil
	}
	out := make([]SSTIPayload, 0, 20)
	seen := make(map[string]bool)
	for _, line := range lines {
		expect, ok := deriveExpectedFromPayload(line)
		if !ok {
			continue
		}
		payload := strings.TrimSpace(line)
		if payload == "" || seen[payload] {
			continue
		}
		seen[payload] = true
		out = append(out, SSTIPayload{
			Name:    "SSTI Arithmetic (PATTT)",
			Payload: payload,
			Check:   expect,
		})
		if len(out) >= 5 {
			break
		}
	}
	return out
}

func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	u, _ := url.Parse(baseURL)
	q := u.Query()

	// High probability params for SSTI
	sstiParams := []string{"template", "view", "name", "id", "q", "page", "redirect"}
	testParams := make(map[string]string)

	if len(q) == 0 {
		for _, sp := range sstiParams {
			testParams[sp] = "1"
		}
	} else {
		for param := range q {
			testParams[param] = q.Get(param)
		}
	}

	allPayloads := append(append([]SSTIPayload{}, SSTIPayloads...), loadPATTTArithmeticPayloads()...)
	baseBodies := make(map[string]string, len(testParams))
	for targetParam := range testParams {
		baseU, _ := url.Parse(baseURL)
		baseQ := baseU.Query()
		for k, v := range testParams {
			baseQ.Set(k, v)
		}
		baseQ.Set(targetParam, "bhyakugan_ssti_control")
		baseU.RawQuery = baseQ.Encode()
		baseTarget := baseU.String()
		baseReq, _ := http.NewRequest("GET", baseTarget, nil)
		utils.SetDefaultHeaders(baseReq, baseTarget)
		baseResp, baseErr := client.Do(baseReq)
		if baseErr == nil {
			baseBodyBytes, _ := io.ReadAll(baseResp.Body)
			baseResp.Body.Close()
			baseBodies[targetParam] = string(baseBodyBytes)
		}
	}

	for _, p := range allPayloads {
		for targetParam := range testParams {
			fuzzU, _ := url.Parse(baseURL)
			fuzzQ := fuzzU.Query()
			for k, v := range testParams {
				fuzzQ.Set(k, v)
			}
			fuzzQ.Set(targetParam, p.Payload)
			fuzzU.RawQuery = fuzzQ.Encode()
			target := fuzzU.String()

			req, _ := http.NewRequest("GET", target, nil)
			utils.SetDefaultHeaders(req, target)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(resp.Body)
			bodyStr := string(bodyBytes)

			// SMART CHECK:
			// 1. Result must be in body
			// 2. Original payload must NOT be in body (to avoid reflection false positive)
			if strings.Contains(bodyStr, p.Check) &&
				!strings.Contains(bodyStr, p.Payload) &&
				(baseBodies[targetParam] == "" || !strings.Contains(baseBodies[targetParam], p.Check)) {
				onFound(core.Finding{
					Type:       "Server-Side Template Injection",
					Target:     target,
					Detail:     fmt.Sprintf("%s confirmed. Found output '%s' in param '%s'", p.Name, p.Check, targetParam),
					Severity:   "Critical",
					Confidence: "confirmed",
				})
				return // Found one, move to next host
			}
		}
	}
}
