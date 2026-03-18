package ssti

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/areksaxyz/bhyakugan/internal/core"
	"github.com/areksaxyz/bhyakugan/internal/payloadrepo"
	"github.com/areksaxyz/bhyakugan/internal/utils"
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
	{"SSTI Freemarker (Alt)", "${99998*8}", "799984"},
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
	case strings.Contains(p, "99998*8"):
		return "799984", true
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
		baseReq, errBaseReq := http.NewRequest("GET", baseTarget, nil)
		if errBaseReq == nil {
			utils.SetDefaultHeaders(baseReq, baseTarget)
			baseResp, baseErr := client.Do(baseReq)
			if baseErr == nil {
				baseBodyBytes, _ := io.ReadAll(io.LimitReader(io.LimitReader(baseResp.Body, 5*1024*1024), 5*1024*1024))
				baseResp.Body.Close()
				baseBodies[targetParam] = string(baseBodyBytes)
			}
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

			req, err := http.NewRequest("GET", target, nil)
			if err != nil {
				continue
			}
			utils.SetDefaultHeaders(req, target)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
			bodyStr := string(bodyBytes)

			// SMART CHECK:
			// 1. Result must be in body
			// 2. Original payload must NOT be in body (to avoid reflection false positive)
			if strings.Contains(bodyStr, p.Check) &&
				!strings.Contains(bodyStr, p.Payload) &&
				(baseBodies[targetParam] == "" || !strings.Contains(baseBodies[targetParam], p.Check)) {

				// --- AUTO EXPLOIT VERIFICATION (New Upgrade via VerificationEngine) ---
				ve := core.NewVerificationEngine(client)

				// Define a "False" payload that should NOT be evaluated or should result in a different value
				// For SSTI, we can use a different arithmetic or just a string that won't match the check.
				verifyPayload := strings.ReplaceAll(p.Payload, "13377331*2", "13377331+7")
				verifyCheck := "13377338"
				if strings.Contains(p.Payload, "131*7") {
					verifyPayload = strings.ReplaceAll(p.Payload, "131*7", "131+7")
					verifyCheck = "138"
				} else if strings.Contains(p.Payload, "'7'*7") {
					verifyPayload = strings.ReplaceAll(p.Payload, "'7'*7", "'8'*2")
					verifyCheck = "88"
				}

				// We use Verify to check if the response changes between two different valid payloads
				// or we can just use the internal logic since SSTI is content-based not just length-based.
				// However, to follow the requested flow:
				res := ve.Verify(baseURL, targetParam, p.Payload, "bhyakugan_ssti_false_control")

				if res.IsConfirmed {
					detail := fmt.Sprintf("%s confirmed via arithmetic evaluation and differential control. %s", p.Name, res.Detail)
					severity := "Critical"

					if secondaryDetail, secondaryConfirmed := runSecondaryArithmeticCheck(baseURL, targetParam, verifyPayload, verifyCheck, testParams, client); secondaryConfirmed {
						detail = detail + " " + secondaryDetail
					} else {
						severity = "High"
						detail = detail + " Secondary arithmetic confirmation did not evaluate, but the primary arithmetic execution signal was verified."
					}

					onFound(core.Finding{
						Type:       "Server-Side Template Injection",
						Target:     target,
						Detail:     detail,
						Severity:   severity,
						Confidence: core.ConfidenceConfirmed,
					})
					return
				}

				if res.IsSignal {
					onFound(core.Finding{
						Type:       "Server-Side Template Injection",
						Target:     target,
						Detail:     fmt.Sprintf("%s arithmetic evaluation signal observed, but only partial differential confirmation was established. %s", p.Name, res.Detail),
						Severity:   "Medium",
						Confidence: core.ConfidenceProbable,
					})
					return
				}
			}
		}
	}
}

func runSecondaryArithmeticCheck(baseURL, targetParam, verifyPayload, verifyCheck string, testParams map[string]string, client *http.Client) (string, bool) {
	vFuzzU, _ := url.Parse(baseURL)
	vFuzzQ := vFuzzU.Query()
	for k, v := range testParams {
		vFuzzQ.Set(k, v)
	}
	vFuzzQ.Set(targetParam, verifyPayload)
	vFuzzU.RawQuery = vFuzzQ.Encode()
	vTarget := vFuzzU.String()

	vReq, _ := http.NewRequest("GET", vTarget, nil)
	utils.SetDefaultHeaders(vReq, vTarget)
	vResp, vErr := client.Do(vReq)
	if vErr != nil {
		return "", false
	}
	vBodyBytes, _ := io.ReadAll(io.LimitReader(io.LimitReader(vResp.Body, 5*1024*1024), 5*1024*1024))
	vResp.Body.Close()
	vBodyStr := string(vBodyBytes)

	if strings.Contains(vBodyStr, verifyCheck) && !strings.Contains(vBodyStr, verifyPayload) {
		return "Secondary arithmetic confirmation matched a distinct evaluated expression.", true
	}
	return "", false
}
