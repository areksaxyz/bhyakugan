package output

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/areksaxyz/bhyakugan/internal/core"
)

var (
	reportDatePattern    = regexp.MustCompile(`(<p>Date: <strong>).*?(</strong></p>)`)
	impactSummaryPattern = regexp.MustCompile(`(?s)<div class="impact-summary">.*?</div>\s*<div class="section-title">`)
)

func mixedReportFixture() ([]core.Finding, []string, string) {
	target := "https://example.com"
	liveHosts := []string{target}
	findings := []core.Finding{
		{
			Type:       "Oracle SQLi (Length Filter Bypass)",
			Target:     "https://example.com/oracle?id=1",
			Detail:     "Payload A (TRUE): 200\nPayload B (FALSE): 500\nConclusion: Boolean-based SQL Injection confirmed (Oracle Length Filter Bypass).\nEvidence Quality: 90/100 | deterministic=true | control_validation=true | response_diff_entropy=true | body_fingerprint=true | fp_risk=low | tier=tier1\nExploit Depth: 3/5 (deterministic_true_false_differential)",
			Severity:   "High",
			Confidence: "confirmed",
		},
		{
			Type:       "SQL Injection (Boolean-Based)",
			Target:     "https://example.com/api/items?id=7",
			Detail:     "Boolean-based SQL injection signal for String Boolean Blind (Single Quote) in param 'id'. Boolean TRUE/FALSE differential observed, but stable body fingerprint was not established. Manual verification required. (Original Len: 120, Baseline Len: 120, True Len: 120, False Len: 120 | control_validation=true | response_diff_stable=true | body_fingerprint=false)\nEvidence Quality: 60/100 | deterministic=true | control_validation=true | response_diff_entropy=true | body_fingerprint=false | fp_risk=medium | tier=tier2\nExploit Depth: 2/5 (behavioral_or_partial_deterministic_signal)",
			Severity:   "High",
			Confidence: "confirmed",
		},
		{
			Type:       "XPath Injection",
			Target:     "https://example.com/akademik?view=dashboard",
			Detail:     "Root Cause: XML Query Differential Signal\nImpact:\n - Deterministic response differential or parser-error signal\n - Manual exploitation confirmation required\nAffected parameters: view\nRepresentative payload evidence (max 3 of 1 vectors):\n1. payload=XPath Boolean Pair param=view signal=Boolean TRUE/FALSE differential observed, but stable body fingerprint was not established. Manual verification required. fingerprint=aaaa1111->bbbb2222 target=https://example.com/akademik?view=%27+or+%271%27%3D%271\nEvidence Quality: 62/100 | deterministic=true | control_validation=true | response_diff_entropy=true | body_fingerprint=false | fp_risk=medium | tier=tier2\nExploit Depth: 2/5 (behavioral_or_partial_deterministic_signal)",
			Severity:   "High",
			Confidence: "confirmed",
		},
		{
			Type:       "Path Discovered",
			Target:     "https://example.com/robots.txt",
			Detail:     "Accessible Path (200 OK, Len: 42)\nEvidence Quality: 45/100 | deterministic=false | control_validation=false | response_diff_entropy=false | body_fingerprint=false | fp_risk=high | tier=tier3\nExploit Depth: 1/5 (heuristic_signal)",
			Severity:   "Info",
			Confidence: "probable",
		},
		{
			Type:       "Recon: Login Form Detected",
			Target:     "https://example.com/login",
			Detail:     "Login form with password input discovered.\nEvidence Quality: 35/100 | deterministic=false | control_validation=false | response_diff_entropy=false | body_fingerprint=false | fp_risk=very-high | tier=tier3\nExploit Depth: 1/5 (heuristic_signal)",
			Severity:   "Info",
			Confidence: "probable",
		},
		{
			Type:       "Recon: JS Sourcemap",
			Target:     "https://example.com/static/app.js.map",
			Detail:     "Javascript sourcemap file discovered. Can be used to recover original source code.\nEvidence Quality: 50/100 | deterministic=false | control_validation=false | response_diff_entropy=false | body_fingerprint=false | fp_risk=high | tier=tier3\nExploit Depth: 1/5 (heuristic_signal)",
			Severity:   "Low",
			Confidence: "probable",
		},
	}
	return findings, liveHosts, target
}

func generateHTMLForTest(t *testing.T, findings []core.Finding, liveHosts []string, target, mode string) string {
	t.Helper()

	tmp := t.TempDir()
	reportPath := filepath.Join(tmp, "report.html")
	if err := GenerateHTML(reportPath, findings, liveHosts, target, mode); err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}
	return string(content)
}

func normalizeHTMLForGolden(html string) string {
	html = strings.ReplaceAll(html, "\r\n", "\n")
	html = reportDatePattern.ReplaceAllString(html, `${1}NORMALIZED_DATE</strong></p>`)
	html = impactSummaryPattern.ReplaceAllString(html, `<div class="section-title">`)

	start := strings.Index(html, `<div class="header">`)
	if start == -1 {
		return strings.TrimSpace(html)
	}
	return strings.TrimSpace(html[start:])
}

func assertGoldenFile(t *testing.T, goldenName, got string) {
	t.Helper()

	goldenPath := filepath.Join("testdata", goldenName)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0755); err != nil {
			t.Fatalf("failed to create golden directory: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0644); err != nil {
			t.Fatalf("failed to update golden file: %v", err)
		}
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("failed to read golden file %s: %v", goldenPath, err)
	}

	if got != string(want) {
		actualPath := filepath.Join(t.TempDir(), goldenName+".actual")
		if err := os.WriteFile(actualPath, []byte(got), 0644); err != nil {
			t.Fatalf("golden mismatch and failed writing actual output: %v", err)
		}
		t.Fatalf("golden mismatch for %s; inspect %s or run with UPDATE_GOLDEN=1", goldenPath, actualPath)
	}
}

func TestBuildConciseRootCauseClusterDetail(t *testing.T) {
	group := []core.Finding{
		{Type: "XPath Injection", Target: "https://example.com/a?id=1", Detail: "Root Cause: XML Query Injection (XPath)\nBehavioral indicator changed"},
		{Type: "XPath Injection", Target: "https://example.com/b?id=1", Detail: "Root Cause: XML Query Injection (XPath)\nBehavioral indicator changed"},
		{Type: "XPath Injection", Target: "https://example.com/c?id=1", Detail: "Root Cause: XML Query Injection (XPath)\nXPath error found: xpathexception"},
	}
	detail := buildConciseRootCauseClusterDetail(group)
	if !strings.Contains(detail, "Affected endpoints: 3") {
		t.Fatalf("expected endpoint count summary, got: %s", detail)
	}
	if strings.Count(detail, "endpoint=") > 3 {
		t.Fatalf("expected representative proof to be limited, got: %s", detail)
	}
}

func TestCountUniqueTargets(t *testing.T) {
	group := []core.Finding{
		{Target: "https://example.com/a?id=1"},
		{Target: "https://example.com/a?id=2"},
		{Target: "https://example.com/b?id=1"},
	}
	if got := countUniqueTargets(group); got != 2 {
		t.Fatalf("expected 2 unique targets, got %d", got)
	}
}

func TestIsReconObservationTier3(t *testing.T) {
	f := core.Finding{
		Type:       "GraphQL Batching",
		Severity:   "Info",
		Confidence: "noisy",
		Detail:     "heuristic signal\nEvidence Quality: 25/100 | deterministic=false | control_validation=false | response_diff_entropy=false | body_fingerprint=false | fp_risk=very-high | tier=tier3",
	}
	if !isReconObservation(f) {
		t.Fatal("expected tier3 signal to be classified as recon observation")
	}
}

func TestIsReconObservationDeterministicHigh(t *testing.T) {
	f := core.Finding{
		Type:       "Oracle SQLi (Length Filter Bypass)",
		Severity:   "High",
		Confidence: "confirmed",
		Detail:     "boolean differential confirmed\nEvidence Quality: 80/100 | deterministic=true | control_validation=true | response_diff_entropy=true | body_fingerprint=true | fp_risk=low | tier=tier1",
	}
	if isReconObservation(f) {
		t.Fatal("expected high deterministic exploit proof to remain a vulnerability finding")
	}
}

func TestGenerateHTMLSeparatesReconObservations(t *testing.T) {
	tmp := t.TempDir()
	reportPath := filepath.Join(tmp, "report.html")

	findings := []core.Finding{
		{
			Type:       "SQL Injection",
			Target:     "https://example.com/login?id=1",
			Detail:     "boolean based diff\nEvidence Quality: 82/100 | deterministic=true | control_validation=true | response_diff_entropy=true | body_fingerprint=true | fp_risk=low | tier=tier1",
			Severity:   "High",
			Confidence: "confirmed",
		},
		{
			Type:       "GraphQL Batching",
			Target:     "https://example.com/graphql",
			Detail:     "heuristic signal\nEvidence Quality: 25/100 | deterministic=false | control_validation=false | response_diff_entropy=false | body_fingerprint=false | fp_risk=very-high | tier=tier3",
			Severity:   "Info",
			Confidence: "noisy",
		},
	}

	if err := GenerateHTML(reportPath, findings, nil, "https://example.com", "public"); err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}
	html := string(content)
	if !strings.Contains(html, "Validated Public Exposures") {
		t.Fatalf("expected validated vulnerability section, got html: %s", html)
	}
	if !strings.Contains(html, "Recon / Attack Surface") {
		t.Fatalf("expected recon observation section count, got html: %s", html)
	}
	if !strings.Contains(html, "SQL Injection") {
		t.Fatal("expected vulnerability finding to remain in findings section")
	}
}

func TestGenerateHTMLSeparatesProbableSignalsFromValidated(t *testing.T) {
	tmp := t.TempDir()
	reportPath := filepath.Join(tmp, "report.html")

	findings := []core.Finding{
		{
			Type:       "SQL Injection (Boolean-Based)",
			Target:     "https://example.com/login?id=1",
			Detail:     "Boolean-based SQL injection signal for String Boolean Blind (Single Quote) in param 'id'. Boolean TRUE/FALSE differential observed, but stable body fingerprint was not established. Manual verification required. (Original Len: 15, Baseline Len: 15, True Len: 15, False Len: 15 | control_validation=true | response_diff_stable=true | body_fingerprint=false)\nEvidence Quality: 60/100 | deterministic=true | control_validation=true | response_diff_entropy=true | body_fingerprint=false | fp_risk=medium | tier=tier2\nExploit Depth: 2/5 (behavioral_or_partial_deterministic_signal)",
			Severity:   "High",
			Confidence: "confirmed",
		},
	}

	if err := GenerateHTML(reportPath, findings, nil, "https://example.com", "public"); err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}
	html := string(content)
	if !strings.Contains(html, "Probable Sensitive Signals") {
		t.Fatalf("expected probable signals section, got html: %s", html)
	}
	if strings.Contains(html, "Validated Scope Count: <strong>1</strong>") {
		t.Fatalf("expected probable SQLi signal to stay out of validated scope count, got html: %s", html)
	}
}

func TestGenerateHTMLReportLevelBucketsAndCountersStayConsistent(t *testing.T) {
	findings, liveHosts, target := mixedReportFixture()
	html := generateHTMLForTest(t, findings, liveHosts, target, "public")

	validated := sectionSlice(html, "Validated Public Exposures", "Probable Sensitive Signals", "Recon / Attack Surface")
	probable := sectionSlice(html, "Probable Sensitive Signals", "Recon / Attack Surface")
	recon := sectionSlice(html, "Recon / Attack Surface")

	if !strings.Contains(validated, "Endpoint Family (example.com/oracle)") {
		t.Fatalf("expected validated vuln in validated section, got: %s", validated)
	}
	if strings.Contains(validated, "Endpoint Family (example.com/api)") || strings.Contains(validated, "XPath Injection") {
		t.Fatalf("expected weak differential findings to stay out of validated section, got: %s", validated)
	}

	if !strings.Contains(probable, "Endpoint Family (example.com/api)") || !strings.Contains(probable, "XPath Injection") {
		t.Fatalf("expected probable SQLi/XPath signals in probable section, got: %s", probable)
	}
	if !strings.Contains(probable, "PROBABLE") {
		t.Fatalf("expected probable confidence labels in probable section, got: %s", probable)
	}
	if strings.Contains(probable, "CONFIRMED") {
		t.Fatalf("expected no confirmed label in probable section, got: %s", probable)
	}
	if !strings.Contains(strings.ToLower(probable), "manual verification required") {
		t.Fatalf("expected manual-verification note in probable section, got: %s", probable)
	}

	if !strings.Contains(recon, "Surface Discovery") ||
		!strings.Contains(recon, "Auth Surface: Login Form") ||
		!strings.Contains(recon, "Recon: JS Sourcemap") {
		t.Fatalf("expected recon findings in recon section, got: %s", recon)
	}

	if !strings.Contains(html, "Validated Scope Count: <strong>1</strong>") {
		t.Fatalf("expected validated scope count to include only validated findings, got html: %s", html)
	}
	if !strings.Contains(html, "Mode: <strong>public</strong>") {
		t.Fatalf("expected report header to include normalized runtime mode, got html: %s", html)
	}

	assertOverviewCount(t, html, "Validated Exposures", 1)
	assertOverviewCount(t, html, "Probable Sensitive Signals", 2)
	assertOverviewCount(t, html, "Recon Surfaces", 3)
	assertOverviewCount(t, html, "Live Hosts", 1)

	assertValidatedSeverityCount(t, html, "critical", 0)
	assertValidatedSeverityCount(t, html, "high", 1)
	assertValidatedSeverityCount(t, html, "medium", 0)
	assertValidatedSeverityCount(t, html, "low", 0)

	if strings.Contains(html, "High</span> Findings") || strings.Contains(html, "Medium</span> Findings") {
		t.Fatalf("expected report sections to be bucket-based, not conflicting severity sections, got html: %s", html)
	}
	if strings.Contains(html, "CONFIRMED") && strings.Contains(html, "Manual verification required") && strings.Contains(probable, "CONFIRMED") {
		t.Fatalf("expected no confirmed+manual-verification contradiction in probable section, got: %s", probable)
	}
}

func TestGenerateHTMLGoldenReportSnapshot(t *testing.T) {
	findings, liveHosts, target := mixedReportFixture()
	html := generateHTMLForTest(t, findings, liveHosts, target, "public")
	assertGoldenFile(t, "mixed_report.golden.html", normalizeHTMLForGolden(html))
}

func TestGenerateHTMLNormalizesLegacyModeInHeader(t *testing.T) {
	findings, liveHosts, target := mixedReportFixture()
	html := generateHTMLForTest(t, findings, liveHosts, target, "lab")
	if !strings.Contains(html, "Mode: <strong>research</strong>") {
		t.Fatalf("expected legacy lab mode to be normalized to research in header, got html: %s", html)
	}
}

func TestCollectAffectedParametersPrefersCommonParametersForCollapsedClusters(t *testing.T) {
	group := []core.Finding{
		{Detail: "Affected parameters: id, name, query, search, user, xml, hl"},
		{Detail: "Affected parameters: id, name, query, search, user, xml, url"},
		{Detail: "Affected parameters: id, name, query, search, user, xml, cmd"},
		{Detail: "Affected parameters: id, name, query, search, user, xml"},
		{Detail: "Affected parameters: id, name, query, search, user, xml, pass"},
	}

	got := collectAffectedParameters(group)
	want := []string{"id", "name", "query", "search", "user", "xml"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expected common parameters %v, got %v", want, got)
	}
}

func sectionSlice(html, title string, nextTitles ...string) string {
	startMarker := ">" + title + "</span> ("
	start := strings.Index(html, startMarker)
	if start == -1 {
		return ""
	}
	end := len(html)
	for _, next := range nextTitles {
		nextMarker := ">" + next + "</span> ("
		if idx := strings.Index(html[start+len(startMarker):], nextMarker); idx != -1 {
			candidate := start + len(startMarker) + idx
			if candidate < end {
				end = candidate
			}
		}
	}
	return html[start:end]
}

func assertOverviewCount(t *testing.T, html, label string, want int) {
	t.Helper()
	labelTag := `<p>` + label + `</p>`
	labelStart := strings.Index(html, labelTag)
	if labelStart == -1 {
		t.Fatalf("missing overview card for label %q", label)
	}
	start := strings.LastIndex(html[:labelStart], "<h3>")
	if start == -1 {
		t.Fatalf("missing overview value for label %q", label)
	}
	start += len("<h3>")
	end := strings.Index(html[start:], "</h3>")
	if end == -1 {
		t.Fatalf("missing overview closing tag for label %q", label)
	}
	got, err := strconv.Atoi(html[start : start+end])
	if err != nil {
		t.Fatalf("failed to parse overview count for %q: %v", label, err)
	}
	if got != want {
		t.Fatalf("expected overview %q count %d, got %d", label, want, got)
	}
}

func assertValidatedSeverityCount(t *testing.T, html, severityClass string, want int) {
	t.Helper()
	title := `<div class="dashboard-title">Validated Severity</div>`
	start := strings.Index(html, title)
	if start == -1 {
		t.Fatal("missing validated severity dashboard")
	}
	section := html[start:]

	prefix := `<div class="card ` + severityClass + `"><h3>`
	cardStart := strings.Index(section, prefix)
	if cardStart == -1 {
		t.Fatalf("missing validated severity card for %q", severityClass)
	}
	cardStart += len(prefix)
	end := strings.Index(section[cardStart:], "</h3>")
	if end == -1 {
		t.Fatalf("missing validated severity closing tag for %q", severityClass)
	}
	got, err := strconv.Atoi(section[cardStart : cardStart+end])
	if err != nil {
		t.Fatalf("failed to parse validated severity count for %q: %v", severityClass, err)
	}
	if got != want {
		t.Fatalf("expected validated severity %q count %d, got %d", severityClass, want, got)
	}
}

func TestGenerateHTMLEscapesUntrustedContent(t *testing.T) {
	tmp := t.TempDir()
	reportPath := filepath.Join(tmp, "report.html")

	findings := []core.Finding{
		{
			Type:       `<script>alert("type")</script>`,
			Target:     `javascript:alert("target")`,
			Detail:     `<img src=x onerror=alert("detail")>`,
			Severity:   "High",
			Confidence: "confirmed",
		},
	}

	if err := GenerateHTML(reportPath, findings, nil, `<svg onload=alert("target")>`, "public"); err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}

	html := string(content)
	if strings.Contains(html, `<script>alert("type")</script>`) {
		t.Fatal("expected finding type to be HTML-escaped")
	}
	if strings.Contains(html, `<img src=x onerror=alert("detail")>`) {
		t.Fatal("expected finding detail to be HTML-escaped")
	}
	if strings.Contains(strings.ToLower(html), `href="javascript:alert(`) {
		t.Fatal("expected unsafe javascript URL to be stripped from report links")
	}
	if !strings.Contains(html, `&lt;script&gt;alert`) {
		t.Fatal("expected escaped finding type to remain visible in report")
	}
}

func TestGenerateHTMLWritesPrivateFile(t *testing.T) {
	tmp := t.TempDir()
	reportPath := filepath.Join(tmp, "report.html")

	findings := []core.Finding{
		{Type: "SQL Injection", Target: "https://example.com", Detail: "confirmed", Severity: "High", Confidence: "confirmed"},
	}

	if err := GenerateHTML(reportPath, findings, nil, "https://example.com", "public"); err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	info, err := os.Stat(reportPath)
	if err != nil {
		t.Fatalf("stat report failed: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("expected report permissions 0600, got %o", got)
	}
}

func TestSaveListWritesPrivateFile(t *testing.T) {
	tmp := t.TempDir()
	listPath := filepath.Join(tmp, "targets.txt")

	if err := SaveList(listPath, []string{"https://example.com"}); err != nil {
		t.Fatalf("SaveList failed: %v", err)
	}

	info, err := os.Stat(listPath)
	if err != nil {
		t.Fatalf("stat list failed: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("expected list permissions 0600, got %o", got)
	}
}
