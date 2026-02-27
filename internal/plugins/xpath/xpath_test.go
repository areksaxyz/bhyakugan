package xpath

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/yupiyy/bhyakugan/internal/core"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func testResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}
}

func TestScanAggregatesSingleFindingPerEndpoint(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			for param, values := range req.URL.Query() {
				raw := strings.ToLower(strings.Join(values, " "))
				if strings.Contains(raw, "bhyakugan_xpath_control") {
					return testResponse(req, http.StatusOK, "normal-response"), nil
				}
				if (param == "query" || param == "xml") && strings.Contains(raw, "' or '1'='1") {
					return testResponse(req, http.StatusOK, "XPathException: invalid predicate"), nil
				}
			}
			return testResponse(req, http.StatusOK, "normal-response"), nil
		}),
	}

	var findings []core.Finding
	Scan("http://example.com/search", client, func(f core.Finding) {
		findings = append(findings, f)
	})

	if len(findings) != 1 {
		t.Fatalf("expected one aggregated finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != "XPath Injection" {
		t.Fatalf("unexpected type %q", f.Type)
	}
	if !strings.Contains(f.Detail, "Affected parameters:") {
		t.Fatal("expected affected parameter summary in detail")
	}
	if strings.Count(f.Detail, "payload=") > 3 {
		t.Fatal("expected at most 3 representative payload lines")
	}
}

func TestEvaluateXPathSignalBehaviorOnlyIsInformational(t *testing.T) {
	base := xpathBaseline{
		bodyLower: "normal response",
		bodyHash:  "base",
		status:    http.StatusOK,
	}
	payload := XPathPayload{Name: "XPath Enumeration", Payload: "//*"}
	signal, severity, confidence, deterministic, matched := evaluateXPathSignal(payload, http.StatusOK, "admin dashboard", base)
	if !matched {
		t.Fatal("expected heuristic behavior-only signal to be captured")
	}
	if severity != "Info" {
		t.Fatalf("expected Info severity, got %q", severity)
	}
	if confidence != "noisy" {
		t.Fatalf("expected noisy confidence, got %q", confidence)
	}
	if deterministic {
		t.Fatal("expected non-deterministic signal")
	}
	if !strings.Contains(strings.ToLower(signal), "heuristic only") {
		t.Fatalf("expected heuristic marker in signal, got %q", signal)
	}
}

func TestScanSkipsIdenticalLoginRedirectFlow(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			resp := testResponse(req, http.StatusFound, strings.Repeat("x", 402))
			resp.Header.Set("Location", "/login")
			return resp, nil
		}),
	}

	var findings []core.Finding
	Scan("http://example.com/protected", client, func(f core.Finding) {
		findings = append(findings, f)
	})

	for _, f := range findings {
		if f.Type == "XPath Injection" || f.Type == "XML Query Injection" {
			t.Fatalf("expected no XPath finding on identical login redirect flow, got %+v", f)
		}
	}
}

func TestScanDetectsBooleanPairDifferential(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			queryLower := strings.ToLower(req.URL.RawQuery)
			if strings.Contains(queryLower, "bhyakugan_xpath_control") {
				return testResponse(req, http.StatusOK, "normal-response"), nil
			}
			if strings.Contains(queryLower, "%27+or+%271%27%3d%271") {
				return testResponse(req, http.StatusOK, "admin-dashboard"), nil
			}
			if strings.Contains(queryLower, "%27+or+%271%27%3d%272") {
				return testResponse(req, http.StatusOK, "normal-response"), nil
			}
			return testResponse(req, http.StatusOK, "normal-response"), nil
		}),
	}

	var findings []core.Finding
	Scan("http://example.com/search", client, func(f core.Finding) {
		findings = append(findings, f)
	})
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].Severity != "High" {
		t.Fatalf("expected High severity for boolean differential, got %q", findings[0].Severity)
	}
	if !strings.Contains(strings.ToLower(findings[0].Detail), "boolean true/false differential confirmed") {
		t.Fatalf("expected boolean differential evidence in detail, got: %s", findings[0].Detail)
	}
}
