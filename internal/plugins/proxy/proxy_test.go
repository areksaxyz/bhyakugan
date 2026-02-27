package proxy

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

func makeResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}
}

func TestProxyHeaderBypassReportedAsSingleRootCause(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			path := req.URL.Path
			for _, p := range internalPaths {
				if path == p {
					// Baseline request without spoofed header should be denied.
					if req.Header.Get("X-Forwarded-For") == "" &&
						req.Header.Get("X-Real-IP") == "" &&
						req.Header.Get("True-Client-IP") == "" &&
						req.Header.Get("Client-IP") == "" &&
						req.Header.Get("X-Remote-IP") == "" {
						return makeResponse(req, http.StatusForbidden, "Forbidden"), nil
					}
					return makeResponse(req, http.StatusOK, "<html><body><h1>admin dashboard root config</h1></body></html>"), nil
				}
			}
			// Keep auxiliary checks quiet for this test.
			return makeResponse(req, http.StatusNotFound, "Not Found"), nil
		}),
	}

	var findings []core.Finding
	Scan("http://example.com", client, func(f core.Finding) {
		findings = append(findings, f)
	})

	if len(findings) != 1 {
		t.Fatalf("expected one root-cause finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != "Improper Trust in HTTP Headers (Proxy Bypass)" {
		t.Fatalf("unexpected finding type: %q", f.Type)
	}
	if !strings.Contains(f.Detail, "Vectors tested:") {
		t.Fatal("expected vector count in detail")
	}
	if !strings.Contains(f.Detail, "Confirmed bypass: yes") {
		t.Fatal("expected confirmed bypass summary in detail")
	}
}
