package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yupiyy/bhyakugan/internal/core"
)

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

	if err := GenerateHTML(reportPath, findings, nil, "https://example.com"); err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}
	html := string(content)
	if !strings.Contains(html, "Observations (1)") {
		t.Fatalf("expected recon observation section count, got html: %s", html)
	}
	if !strings.Contains(html, "SQL Injection") {
		t.Fatal("expected vulnerability finding to remain in findings section")
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

	if err := GenerateHTML(reportPath, findings, nil, `<svg onload=alert("target")>`); err != nil {
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

	if err := GenerateHTML(reportPath, findings, nil, "https://example.com"); err != nil {
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
