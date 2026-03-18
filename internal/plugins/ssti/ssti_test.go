package ssti

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/areksaxyz/bhyakugan/internal/core"
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

func TestScanDetectsArithmeticExecutionWithoutSecondaryVariant(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			value := req.URL.Query().Get("q")
			switch {
			case strings.Contains(value, "{{13377331*2}}"):
				return testResponse(req, http.StatusOK, "Rendered Result: 26754662"), nil
			case strings.Contains(value, "bhyakugan_baseline_control"),
				strings.Contains(value, "bhyakugan_ssti_control"),
				strings.Contains(value, "bhyakugan_ssti_false_control"),
				strings.Contains(value, "{{13377331+7}}"):
				return testResponse(req, http.StatusOK, `<html><body><h1>Template Preview</h1><div>Status: draft</div></body></html>`), nil
			default:
				return testResponse(req, http.StatusOK, `<html><body><h1>Template Preview</h1><div>Status: draft</div></body></html>`), nil
			}
		}),
	}

	var findings []core.Finding
	Scan("http://example.com/template?q=hello", client, func(f core.Finding) {
		findings = append(findings, f)
	})

	if len(findings) != 1 {
		t.Fatalf("expected one SSTI finding, got %d", len(findings))
	}
	if findings[0].Type != "Server-Side Template Injection" {
		t.Fatalf("expected SSTI type, got %q", findings[0].Type)
	}
	if findings[0].Confidence != core.ConfidenceConfirmed {
		t.Fatalf("expected confirmed confidence, got %q", findings[0].Confidence)
	}
	if !strings.Contains(findings[0].Detail, "Secondary arithmetic confirmation did not evaluate") {
		t.Fatalf("expected detail to mention secondary confirmation fallback, got %q", findings[0].Detail)
	}
}

func TestScanIgnoresPureReflection(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return testResponse(req, http.StatusOK, "Echo: "+req.URL.Query().Get("q")), nil
		}),
	}

	var findings []core.Finding
	Scan("http://example.com/template?q=hello", client, func(f core.Finding) {
		findings = append(findings, f)
	})

	if len(findings) != 0 {
		t.Fatalf("expected no SSTI finding on pure reflection, got %+v", findings)
	}
}
