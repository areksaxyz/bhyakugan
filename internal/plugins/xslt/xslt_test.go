package xslt

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
			for _, values := range req.URL.Query() {
				raw := strings.ToLower(strings.Join(values, " "))
				if strings.Contains(raw, "bhyakugan_xslt_control") {
					return testResponse(req, http.StatusOK, "normal-response"), nil
				}
				if strings.Contains(raw, "document('/etc/passwd')") || strings.Contains(raw, "php:function('readfile'") {
					return testResponse(req, http.StatusOK, "root:x:0:0:root:/root:/bin/bash"), nil
				}
				if strings.Contains(raw, "system-property('xsl:vendor')") {
					return testResponse(req, http.StatusOK, "<?xml version=\"1.0\"?><error>libxslt error</error>"), nil
				}
			}
			return testResponse(req, http.StatusOK, "normal-response"), nil
		}),
	}

	var findings []core.Finding
	Scan("http://example.com/api", client, func(f core.Finding) {
		findings = append(findings, f)
	})

	if len(findings) != 1 {
		t.Fatalf("expected one aggregated finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != "XSLT Injection" {
		t.Fatalf("unexpected type %q", f.Type)
	}
	if !strings.Contains(f.Detail, "Affected parameters:") {
		t.Fatal("expected affected parameter summary in detail")
	}
	if strings.Count(f.Detail, "payload=") > 3 {
		t.Fatal("expected at most 3 representative payload lines")
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
		if f.Type == "XSLT Injection" || f.Type == "Template Engine Injection" {
			t.Fatalf("expected no XSLT finding on identical login redirect flow, got %+v", f)
		}
	}
}
