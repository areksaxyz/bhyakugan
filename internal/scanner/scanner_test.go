package scanner

import (
	"strings"
	"testing"

	"github.com/yupiyy/bhyakugan/internal/core"
)

func TestEvaluateFindingStrictRejectsProbable(t *testing.T) {
	f := core.Finding{
		Type:       "SQL Injection",
		Target:     "https://example.com/api?id=1",
		Detail:     "Potential timing deviation observed.",
		Severity:   "High",
		Confidence: "probable",
	}

	_, ok := EvaluateFinding("strict", f)
	if ok {
		t.Fatal("expected strict mode to reject probable finding")
	}
}

func TestEvaluateFindingStrictAcceptsConfirmedHigh(t *testing.T) {
	f := core.Finding{
		Type:       "SQL Injection",
		Target:     "https://example.com/api?id=1",
		Detail:     "SQLi confirmed via error-based payload.",
		Severity:   "High",
		Confidence: "confirmed",
	}

	processed, ok := EvaluateFinding("strict", f)
	if !ok {
		t.Fatal("expected strict mode to keep confirmed high finding")
	}
	if processed.Confidence != "confirmed" {
		t.Fatalf("expected normalized confidence confirmed, got %q", processed.Confidence)
	}
}

func TestEvaluateFindingStrictRejectsConfirmedMedium(t *testing.T) {
	f := core.Finding{
		Type:       "GraphQL Introspection",
		Target:     "https://example.com/graphql",
		Detail:     "Introspection query enabled.",
		Severity:   "Medium",
		Confidence: "confirmed",
	}

	_, ok := EvaluateFinding("strict", f)
	if ok {
		t.Fatal("expected strict mode to reject confirmed medium finding")
	}
}

func TestEvaluateFindingBalancedKeepsProbable(t *testing.T) {
	f := core.Finding{
		Type:       "Proxy Misconfiguration",
		Target:     "https://example.com",
		Detail:     "Authentication bypass indicator found.",
		Severity:   "High",
		Confidence: "probable",
	}

	_, ok := EvaluateFinding("balanced", f)
	if !ok {
		t.Fatal("expected balanced mode to keep probable finding")
	}
}

func TestEvaluateFindingAggressiveKeepsNoisy(t *testing.T) {
	f := core.Finding{
		Type:       "Potential Header Leak",
		Target:     "https://example.com",
		Detail:     "Verification failed due network jitter.",
		Severity:   "Low",
		Confidence: "noisy",
	}

	_, ok := EvaluateFinding("aggressive", f)
	if !ok {
		t.Fatal("expected aggressive mode to keep noisy finding")
	}
}

func TestEvaluateFindingProbableCriticalDowngradedToHigh(t *testing.T) {
	f := core.Finding{
		Type:       "SAML Vulnerability",
		Target:     "https://example.com/saml/acs",
		Detail:     "Server accepted unsigned assertion (unverified flow).",
		Severity:   "Critical",
		Confidence: "probable",
	}

	processed, ok := EvaluateFinding("aggressive", f)
	if !ok {
		t.Fatal("expected aggressive mode to keep finding")
	}
	if processed.Severity != "High" {
		t.Fatalf("expected severity downgrade to High, got %q", processed.Severity)
	}
}

func TestEvaluateFindingNoisyHighDowngradedToLow(t *testing.T) {
	f := core.Finding{
		Type:       "Prototype Pollution",
		Target:     "https://example.com/api",
		Detail:     "Unverified signal only.",
		Severity:   "High",
		Confidence: "noisy",
	}

	processed, ok := EvaluateFinding("aggressive", f)
	if !ok {
		t.Fatal("expected aggressive mode to keep finding")
	}
	if processed.Severity != "Low" {
		t.Fatalf("expected severity downgrade to Low, got %q", processed.Severity)
	}
}

func TestEvaluateFindingModeAliasBountyActsStrict(t *testing.T) {
	f := core.Finding{
		Type:       "SQL Injection",
		Target:     "https://example.com/api?id=1",
		Detail:     "Potential timing deviation observed.",
		Severity:   "High",
		Confidence: "probable",
	}

	_, ok := EvaluateFinding("bounty", f)
	if ok {
		t.Fatal("expected bounty alias (strict profile) to reject probable finding")
	}
}

func TestEvaluateFindingModeAliasLabActsAggressive(t *testing.T) {
	f := core.Finding{
		Type:       "Potential Header Leak",
		Target:     "https://example.com",
		Detail:     "Verification failed due network jitter.",
		Severity:   "Low",
		Confidence: "noisy",
	}

	_, ok := EvaluateFinding("lab", f)
	if !ok {
		t.Fatal("expected lab alias (aggressive profile) to keep noisy finding")
	}
}

func TestEvaluateFindingWithOptionsStrictValidationRejectsHeuristicSignals(t *testing.T) {
	f := core.Finding{
		Type:       "Cross-Site WebSocket Hijacking",
		Target:     "https://example.com/ws",
		Detail:     "Server accepted cross-origin handshake. No proof of authenticated action/session takeover yet.",
		Severity:   "High",
		Confidence: "probable",
	}

	_, ok := EvaluateFindingWithOptions("aggressive", true, f)
	if ok {
		t.Fatal("expected strict validation to reject heuristic-only websocket signal")
	}
}

func TestEvaluateFindingWithOptionsStrictValidationRequiresSAMLControlTest(t *testing.T) {
	f := core.Finding{
		Type:       "SAML Vulnerability",
		Target:     "https://example.com/saml/acs",
		Detail:     "Server accepted unsigned response but no control validation.",
		Severity:   "High",
		Confidence: "confirmed",
	}

	_, ok := EvaluateFindingWithOptions("aggressive", true, f)
	if ok {
		t.Fatal("expected strict validation to reject SAML finding without control-test:passed")
	}
}

func TestEvaluateFindingWithOptionsStrictValidationAcceptsSAMLWithControlTest(t *testing.T) {
	f := core.Finding{
		Type:       "SAML Vulnerability",
		Target:     "https://example.com/saml/acs",
		Detail:     "control-test:passed and explicit exploit chain evidence",
		Severity:   "High",
		Confidence: "confirmed",
	}

	_, ok := EvaluateFindingWithOptions("aggressive", true, f)
	if !ok {
		t.Fatal("expected strict validation to keep SAML finding with explicit control-test evidence")
	}
}

func TestBuildFindingDedupeKeyNormalizesQueryAndNumericNoise(t *testing.T) {
	f1 := core.Finding{
		Type:   "XSLT Injection",
		Target: "https://example.com/profile?xml=1",
		Detail: "Time-Based SQLi signal (req1=5.20s req2=5.10s threshold=4.00s).",
	}
	f2 := core.Finding{
		Type:   "XSLT Injection",
		Target: "https://example.com/profile?xml=2",
		Detail: "Time-Based SQLi signal (req1=5.20s req2=5.10s threshold=4.00s).",
	}
	k1 := BuildFindingDedupeKey(f1)
	k2 := BuildFindingDedupeKey(f2)
	if k1 != k2 {
		t.Fatal("expected dedupe key to match for same endpoint/class/proof shape")
	}
}

func TestExecutionProofSignatureNormalizesNumericNoise(t *testing.T) {
	s1 := executionProofSignature("Time-Based SQLi signal (req1=5.20s req2=5.10s threshold=4.00s).")
	s2 := executionProofSignature("Time-Based SQLi signal (req1=8.90s req2=9.00s threshold=6.50s).")
	if s1 != s2 {
		t.Fatalf("expected normalized signatures to match, got %q vs %q", s1, s2)
	}
}

func TestBuildFindingDedupeKeyDiffersAcrossClasses(t *testing.T) {
	f1 := core.Finding{
		Type:   "XSLT Injection",
		Target: "https://example.com/profile?xml=1",
		Detail: "Matched deterministic marker: root:x:",
	}
	f2 := core.Finding{
		Type:   "XPath Injection",
		Target: "https://example.com/profile?xml=1",
		Detail: "Matched deterministic marker: root:x:",
	}
	if BuildFindingDedupeKey(f1) == BuildFindingDedupeKey(f2) {
		t.Fatal("expected dedupe key to differ for different vulnerability classes")
	}
}

func TestEnrichFindingForReportingAddsRootCauseAndQuality(t *testing.T) {
	f := core.Finding{
		Type:   "GraphQL Introspection",
		Target: "https://example.com/graphql",
		Detail: "Introspection is enabled.",
	}
	out := EnrichFindingForReporting(f)
	if out.Detail == f.Detail {
		t.Fatal("expected enriched detail with extra metadata")
	}
	if !containsIgnoreCase(out.Detail, "root cause:") {
		t.Fatal("expected root cause annotation in detail")
	}
	if !containsIgnoreCase(out.Detail, "evidence quality:") {
		t.Fatal("expected evidence quality annotation in detail")
	}
	if !containsIgnoreCase(out.Detail, "exploit depth:") {
		t.Fatal("expected exploit depth annotation in detail")
	}
}

func TestExtractEvidenceQualityScore(t *testing.T) {
	detail := "foo\nEvidence Quality: 78/100 | deterministic=true"
	score, ok := ExtractEvidenceQualityScore(detail)
	if !ok {
		t.Fatal("expected evidence quality score to be parsed")
	}
	if score != 78 {
		t.Fatalf("expected score 78, got %d", score)
	}
}

func TestEvaluateFindingEvidenceSuppressionDowngradesToInfo(t *testing.T) {
	f := core.Finding{
		Type:     "Sensitive Data Exposure",
		Target:   "https://example.com/.env",
		Detail:   "heuristic signal only\nEvidence Quality: 25/100 | deterministic=false | control_validation=false | response_diff_entropy=false | body_fingerprint=false | fp_risk=very-high | tier=tier3",
		Severity: "Critical",
	}
	processed, ok := EvaluateFindingWithOptions("aggressive", false, f)
	if !ok {
		t.Fatal("expected aggressive mode to keep finding for informational visibility")
	}
	if processed.Severity != "Info" {
		t.Fatalf("expected severity Info after suppression, got %q", processed.Severity)
	}
	if processed.Confidence != "noisy" {
		t.Fatalf("expected confidence noisy after suppression, got %q", processed.Confidence)
	}
}

func TestEvaluateFindingVeryHighFPRiskCannotStayCritical(t *testing.T) {
	f := core.Finding{
		Type:       "Sensitive Data Exposure",
		Target:     "https://example.com/secret",
		Detail:     "candidate signal\nEvidence Quality: 35/100 | deterministic=true | control_validation=false | response_diff_entropy=false | body_fingerprint=false | fp_risk=very-high | tier=tier3",
		Severity:   "Critical",
		Confidence: "confirmed",
	}
	processed, ok := EvaluateFindingWithOptions("aggressive", false, f)
	if !ok {
		t.Fatal("expected finding to remain visible in aggressive mode")
	}
	if processed.Severity == "Critical" || processed.Severity == "High" {
		t.Fatalf("expected very-high fp risk to cap severity below High, got %q", processed.Severity)
	}
}

func TestEvaluateFindingQualitySixtyCannotStayHigh(t *testing.T) {
	f := core.Finding{
		Type:       "Sensitive Data Exposure",
		Target:     "https://example.com/secret",
		Detail:     "candidate signal\nEvidence Quality: 60/100 | deterministic=true | control_validation=false | response_diff_entropy=true | body_fingerprint=false | fp_risk=medium | tier=tier2",
		Severity:   "High",
		Confidence: "confirmed",
	}
	processed, ok := EvaluateFindingWithOptions("aggressive", false, f)
	if !ok {
		t.Fatal("expected finding to remain visible in aggressive mode")
	}
	if processed.Severity == "High" || processed.Severity == "Critical" {
		t.Fatalf("expected quality=60 signal to be capped below High, got %q", processed.Severity)
	}
}

func TestEvaluateFindingDeterministicOracleProofMinHigh(t *testing.T) {
	f := core.Finding{
		Type:       "Oracle SQLi (Length Filter Bypass)",
		Target:     "https://example.com/vuln/oracle",
		Detail:     "Payload A (TRUE): ... -> HTTP 200\nPayload B (FALSE): ... -> HTTP 500\nConclusion: Boolean-based SQL Injection confirmed (Oracle Length Filter Bypass).\nReason: Oracle Error (Divisor is equal to zero) triggered by False payload.\nEvidence Quality: 70/100 | deterministic=true | control_validation=true | response_diff_entropy=false | body_fingerprint=false | fp_risk=medium | tier=tier2",
		Severity:   "Medium",
		Confidence: "probable",
	}
	processed, ok := EvaluateFindingWithOptions("aggressive", false, f)
	if !ok {
		t.Fatal("expected finding to remain visible in aggressive mode")
	}
	if processed.Severity != "High" && processed.Severity != "Critical" {
		t.Fatalf("expected deterministic oracle proof to be at least High, got %q", processed.Severity)
	}
}

func TestEvaluateFindingProxyBypassSensitiveMinHigh(t *testing.T) {
	f := core.Finding{
		Type:       "Improper Trust in HTTP Headers (Proxy Bypass)",
		Target:     "https://example.com",
		Detail:     "Confirmed bypass: yes (headers=4, endpoints=2)\nRepresentative evidence:\n1. header=X-Forwarded-For endpoint=https://example.com/admin signal=sensitive-content fingerprint=aaaa1111->bbbb2222\nEvidence Quality: 72/100 | deterministic=true | control_validation=true | response_diff_entropy=false | body_fingerprint=true | fp_risk=high | tier=tier1",
		Severity:   "Medium",
		Confidence: "probable",
	}
	processed, ok := EvaluateFindingWithOptions("aggressive", false, f)
	if !ok {
		t.Fatal("expected finding to remain visible in aggressive mode")
	}
	if processed.Severity != "High" && processed.Severity != "Critical" {
		t.Fatalf("expected proxy auth-bypass proof to be at least High, got %q", processed.Severity)
	}
}

func TestEvaluateFindingXPathHeuristicCappedToInfo(t *testing.T) {
	f := core.Finding{
		Type:       "XPath Injection",
		Target:     "https://example.com/?id=%2F%2F*",
		Detail:     "Behavioral indicator changed: admin (heuristic only; no boolean/count/error deterministic proof)\nEvidence Quality: 50/100 | deterministic=false | control_validation=false | response_diff_entropy=true | body_fingerprint=false | fp_risk=high | tier=tier3",
		Severity:   "High",
		Confidence: "probable",
	}
	processed, ok := EvaluateFindingWithOptions("aggressive", false, f)
	if !ok {
		t.Fatal("expected aggressive mode to keep finding for visibility")
	}
	if processed.Severity != "Info" {
		t.Fatalf("expected XPath heuristic-only signal to be capped at Info, got %q", processed.Severity)
	}
}

func TestEvaluateFindingSQLErrorOnlyCappedToMedium(t *testing.T) {
	f := core.Finding{
		Type:       "SQL Injection",
		Target:     "https://example.com/?p=%27",
		Detail:     "Error-based SQL signal: found MySQL error marker (you have an error in your sql syntax). control_validation=true (marker absent in baseline), but boolean/time/union/data-extraction proof not confirmed.\nEvidence Quality: 60/100 | deterministic=true | control_validation=true | response_diff_entropy=false | body_fingerprint=false | fp_risk=medium | tier=tier2",
		Severity:   "Critical",
		Confidence: "confirmed",
	}
	processed, ok := EvaluateFindingWithOptions("aggressive", false, f)
	if !ok {
		t.Fatal("expected aggressive mode to keep finding")
	}
	if processed.Severity != "Medium" {
		t.Fatalf("expected error-only SQL signal to be capped to Medium, got %q", processed.Severity)
	}
}

func containsIgnoreCase(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func TestIsLikelyStaticAssetURL(t *testing.T) {
	if !isLikelyStaticAssetURL("https://example.com/wp-includes/js/index.min.js?ver=6.7.1") {
		t.Fatal("expected JS asset with query string to be treated as static")
	}
	if isLikelyStaticAssetURL("https://example.com/api/fetch?url=http://169.254.169.254/latest/meta-data/") {
		t.Fatal("expected dynamic API endpoint to not be treated as static asset")
	}
}
