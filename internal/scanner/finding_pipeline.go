package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/areksaxyz/bhyakugan/internal/core"
)

var (
	urlSanitizerRegex      = regexp.MustCompile(`https?://[^\s]+`)
	numberSanitizerRegex   = regexp.MustCompile(`\d+(?:\.\d+)?`)
	spaceNormalizerRegex   = regexp.MustCompile(`\s+`)
	evidenceQualityRegex   = regexp.MustCompile(`(?i)evidence quality:\s*([0-9]{1,3})/100`)
	exploitDepthRegex      = regexp.MustCompile(`(?i)exploit depth:\s*([1-5])\s*/\s*5`)
	fpRiskRegex            = regexp.MustCompile(`(?i)fp_risk=([a-z-]+)`)
	trailingSymbolSanitize = regexp.MustCompile(`[;,\.\)\]\}]+$`)
)

type findingDeduper struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

type evidenceQuality struct {
	Score               int
	Deterministic       bool
	ControlValidated    bool
	ResponseDiffEntropy bool
	BodyFingerprint     bool
	FPRisk              string
	Tier                string
}

func newFindingDeduper() *findingDeduper {
	return &findingDeduper{
		seen: make(map[string]struct{}),
	}
}

func (d *findingDeduper) ShouldEmit(f core.Finding) bool {
	key := BuildFindingDedupeKey(f)
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.seen[key]; exists {
		return false
	}
	d.seen[key] = struct{}{}
	return true
}

// BuildFindingDedupeKey returns hash(endpoint + vulnerability_class + execution_proof).
func BuildFindingDedupeKey(f core.Finding) string {
	raw := fmt.Sprintf("%s|%s|%s",
		canonicalEndpoint(f.Target),
		vulnerabilityClass(f),
		executionProofSignature(f.Detail),
	)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func EnrichFindingForReporting(f core.Finding) core.Finding {
	f = attachRootCause(f)
	f = attachEvidenceQuality(f)
	return f
}

// NormalizedVulnerabilityClass exposes class normalization for cross-package collapsing logic.
func NormalizedVulnerabilityClass(f core.Finding) string {
	return vulnerabilityClass(f)
}

// ExecutionProofSignature exposes normalized proof-signature extraction.
func ExecutionProofSignature(detail string) string {
	return executionProofSignature(detail)
}

func ExtractEvidenceQualityScore(detail string) (int, bool) {
	m := evidenceQualityRegex.FindStringSubmatch(detail)
	if len(m) != 2 {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	if n < 0 {
		n = 0
	}
	if n > 100 {
		n = 100
	}
	return n, true
}

func ExtractExploitDepth(detail string) (int, bool) {
	m := exploitDepthRegex.FindStringSubmatch(detail)
	if len(m) != 2 {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	if n < 1 {
		n = 1
	}
	if n > 5 {
		n = 5
	}
	return n, true
}

func canonicalEndpoint(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return stripQueryAndFragment(trimmed)
	}
	u.RawQuery = ""
	u.Fragment = ""
	cleaned := strings.TrimSpace(u.String())
	if cleaned == "" {
		return stripQueryAndFragment(trimmed)
	}
	if strings.HasSuffix(cleaned, "/") && u.Path != "/" {
		return strings.TrimSuffix(cleaned, "/")
	}
	return cleaned
}

func stripQueryAndFragment(s string) string {
	if idx := strings.Index(s, "?"); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.Index(s, "#"); idx != -1 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

func vulnerabilityClass(f core.Finding) string {
	t := strings.ToLower(strings.TrimSpace(f.Type))
	switch {
	case strings.Contains(t, "server-side template injection"),
		strings.Contains(t, "xslt injection"):
		return "template_engine_injection"
	case strings.Contains(t, "xpath injection"):
		return "xml_query_injection"
	case strings.Contains(t, "graphql introspection"):
		return "graphql_introspection"
	case strings.Contains(t, "cross-site websocket hijacking"):
		return "websocket_origin_policy_misconfiguration"
	case strings.Contains(t, "sql injection"):
		return "sql_injection"
	case strings.Contains(t, "nosql injection"):
		return "nosql_injection"
	default:
		return strings.ReplaceAll(t, " ", "_")
	}
}

func executionProofSignature(detail string) string {
	d := strings.ToLower(strings.TrimSpace(detail))
	if d == "" {
		return "none"
	}
	// Keep the first line as proof anchor, then sanitize noise.
	firstLine := strings.TrimSpace(strings.SplitN(d, "\n", 2)[0])
	if firstLine == "" {
		firstLine = d
	}
	firstLine = urlSanitizerRegex.ReplaceAllString(firstLine, "url")
	firstLine = numberSanitizerRegex.ReplaceAllString(firstLine, "n")
	firstLine = spaceNormalizerRegex.ReplaceAllString(firstLine, " ")
	firstLine = trailingSymbolSanitize.ReplaceAllString(firstLine, "")
	if len(firstLine) > 220 {
		firstLine = strings.TrimSpace(firstLine[:220])
	}
	if firstLine == "" {
		return "none"
	}
	return firstLine
}

func attachRootCause(f core.Finding) core.Finding {
	if strings.Contains(strings.ToLower(f.Detail), "root cause:") {
		return f
	}
	class := vulnerabilityClass(f)
	var rootCauseBlock string
	switch class {
	case "template_engine_injection":
		rootCauseBlock = "Root Cause: Template Engine Injection\nImpact:\n - SSTI-style expression execution\n - XSLT injection\n - LFI via document()/file-read primitives"
	case "xml_query_injection":
		rootCauseBlock = "Root Cause: XML Query Injection\nImpact:\n - XPath predicate manipulation\n - Authentication filter bypass\n - XML data enumeration"
	case "graphql_introspection":
		rootCauseBlock = "Root Cause: GraphQL Schema Discovery Exposure\nImpact:\n - API surface mapping\n - Faster attack path enumeration"
	case "websocket_origin_policy_misconfiguration":
		rootCauseBlock = "Root Cause: Cross-Origin WebSocket Policy Misconfiguration\nImpact:\n - Cross-site handshake acceptance\n - Potential CSWSH precondition (session takeover not proven)"
	default:
		return f
	}
	detail := strings.TrimSpace(f.Detail)
	if detail == "" {
		f.Detail = rootCauseBlock
		return f
	}
	f.Detail = detail + "\n" + rootCauseBlock
	return f
}

func attachEvidenceQuality(f core.Finding) core.Finding {
	detail := strings.TrimSpace(f.Detail)
	q, hasQuality := deriveEvidenceQuality(f)
	if !hasQuality {
		qualityLine := fmt.Sprintf("Evidence Quality: %d/100 | deterministic=%t | control_validation=%t | response_diff_entropy=%t | body_fingerprint=%t | fp_risk=%s | tier=%s",
			q.Score, q.Deterministic, q.ControlValidated, q.ResponseDiffEntropy, q.BodyFingerprint, q.FPRisk, q.Tier)
		if detail == "" {
			detail = qualityLine
		} else {
			detail = detail + "\n" + qualityLine
		}
	}

	if _, ok := ExtractExploitDepth(detail); !ok {
		depth, reason := deriveExploitDepth(f, q)
		depthLine := fmt.Sprintf("Exploit Depth: %d/5 (%s)", depth, reason)
		if detail == "" {
			detail = depthLine
		} else {
			detail = detail + "\n" + depthLine
		}
	}
	f.Detail = detail

	if strings.TrimSpace(string(f.Confidence)) == "" {
		f.Confidence = confidenceFromEvidenceScore(q.Score)
	}
	return f
}

func extractEvidenceQualityFromDetail(detail string) (evidenceQuality, bool) {
	score, ok := ExtractEvidenceQualityScore(detail)
	if !ok {
		return evidenceQuality{}, false
	}
	lower := strings.ToLower(detail)
	qual := evidenceQuality{
		Score:               score,
		Deterministic:       strings.Contains(lower, "deterministic=true"),
		ControlValidated:    strings.Contains(lower, "control_validation=true"),
		ResponseDiffEntropy: strings.Contains(lower, "response_diff_entropy=true"),
		BodyFingerprint:     strings.Contains(lower, "body_fingerprint=true"),
		FPRisk:              "very-high",
	}
	if m := fpRiskRegex.FindStringSubmatch(lower); len(m) == 2 {
		qual.FPRisk = strings.TrimSpace(m[1])
	}
	qual.Tier = evidenceTier(qual)
	return qual, true
}

func deriveEvidenceQuality(f core.Finding) (evidenceQuality, bool) {
	if parsed, ok := extractEvidenceQualityFromDetail(f.Detail); ok {
		return parsed, true
	}
	return scoreEvidenceQuality(f), false
}

func scoreEvidenceQuality(f core.Finding) evidenceQuality {
	text := strings.ToLower(strings.TrimSpace(f.Type + " " + f.Detail))
	score := 25

	deterministicMarkers := []string{
		"confirmed", "matched", "output marker", "root:x:", "ora-", "xpath error found",
		"status code difference", "authenticated action", "session-auth-confirmed", "deterministic=true",
		"verified", "secret match", "pattern matched", "discovered", "found sensitive", "api path", "pattern", "secret leak", "sensitive file ref",
	}
	controlMarkers := []string{
		"control", "baseline", "z=", "z-score", "triple checked", "absent in control",
		"control validation", "verification", "verified", "stable", "control_validation=true",
	}
	diffMarkers := []string{
		"delta", "deviation", "diff", "diverged", "difference", "entropy", "response_diff_entropy=true",
	}
	fingerprintMarkers := []string{
		"fingerprint", "hash", "body hash", "body-hash", "body_fingerprint=true",
	}
	weakMarkers := []string{
		"no proof", "unverified", "heuristic", "potential ", "not direct", "signal only",
		"manual verification required", "needs manual verification",
	}

	fmt.Printf("[DEBUG] Scoring: %s, deterministic: %v\n", text, hasAnyMarker(text, deterministicMarkers))
	deterministic := hasAnyMarker(text, deterministicMarkers)
	controlValidated := hasAnyMarker(text, controlMarkers)
	responseDiff := hasAnyMarker(text, diffMarkers)
	bodyFingerprint := hasAnyMarker(text, fingerprintMarkers)
	weakSignal := hasAnyMarker(text, weakMarkers)

	if deterministic {
		score += 25
	}
	if controlValidated {
		score += 20
	}
	if responseDiff {
		score += 15
	}
	if bodyFingerprint {
		score += 10
	}
	if weakSignal {
		score -= 25
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return evidenceQuality{
		Score:               score,
		Deterministic:       deterministic,
		ControlValidated:    controlValidated,
		ResponseDiffEntropy: responseDiff,
		BodyFingerprint:     bodyFingerprint,
		FPRisk:              fpRiskLabel(score),
		Tier:                evidenceTier(evidenceQuality{Score: score, Deterministic: deterministic, ControlValidated: controlValidated, ResponseDiffEntropy: responseDiff, BodyFingerprint: bodyFingerprint}),
	}
}

func evidenceTier(q evidenceQuality) string {
	switch {
	case q.Deterministic && q.ControlValidated && (q.ResponseDiffEntropy || q.BodyFingerprint || q.Score >= 75):
		return "tier1"
	case (q.Deterministic && q.ControlValidated) || (q.ControlValidated && (q.ResponseDiffEntropy || q.BodyFingerprint)) || q.Score >= 55:
		return "tier2"
	default:
		return "tier3"
	}
}

func confidenceFromEvidenceScore(score int) core.FindingConfidence {
	switch {
	case score >= 80:
		return core.ConfidenceConfirmed
	case score >= 45:
		return core.ConfidenceProbable
	default:
		return core.ConfidenceNoisy
	}
}

func fpRiskLabel(score int) string {
	switch {
	case score >= 80:
		return "low"
	case score >= 60:
		return "medium"
	case score >= 40:
		return "high"
	default:
		return "very-high"
	}
}

func hasAnyMarker(text string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func deriveExploitDepth(f core.Finding, q evidenceQuality) (int, string) {
	t := strings.ToLower(strings.TrimSpace(f.Type))
	d := strings.ToLower(strings.TrimSpace(f.Detail))

	if strings.Contains(t, "remote code execution") ||
		strings.Contains(d, "uid=0(") ||
		strings.Contains(d, "rce confirmed") {
		return 5, "rce_or_direct_code_execution"
	}

	if strings.Contains(d, "privilege escalation confirmed") ||
		strings.Contains(d, "session-auth-confirmed") ||
		(strings.Contains(t, "improper trust in http headers") && strings.Contains(d, "confirmed bypass: yes")) {
		return 4, "auth_or_privilege_boundary_bypass"
	}
	if strings.Contains(d, "root:x:0:0:") ||
		strings.Contains(d, "app_key") ||
		strings.Contains(d, "security-credentials") ||
		strings.Contains(d, "instance-id") {
		return 4, "direct_sensitive_data_exposure"
	}

	if strings.Contains(d, "boolean true/false differential confirmed") ||
		strings.Contains(d, "count() differential confirmed") ||
		strings.Contains(d, "payload a (true)") && strings.Contains(d, "payload b (false)") {
		return 3, "deterministic_true_false_differential"
	}
	if strings.Contains(d, "xpath error found") {
		return 3, "deterministic_parser_error"
	}

	if strings.Contains(d, "error-based sql signal") ||
		strings.Contains(d, "time-based sqli signal") ||
		(q.Deterministic && q.ControlValidated) {
		return 2, "behavioral_or_partial_deterministic_signal"
	}
	if strings.Contains(d, "behavioral indicator changed") ||
		strings.Contains(d, "heuristic only") ||
		strings.Contains(d, "signal only") {
		return 1, "heuristic_signal"
	}

	if q.Score >= 75 && q.Deterministic && q.ControlValidated {
		return 3, "deterministic_validated_signal"
	}
	if q.Score >= 55 {
		return 2, "moderate_signal_strength"
	}
	return 1, "low_signal_strength"
}
