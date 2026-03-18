package proxy

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

func makeResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}
}

func TestProxyHeaderBypassAndBehavioralTrust(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			path := req.URL.Path

			// Scenario 1: Bypass for /admin
			if path == "/admin" {
				if req.Header.Get("X-Forwarded-For") == "127.0.0.1" {
					return makeResponse(req, http.StatusOK, "<html><body><h1>admin dashboard</h1></body></html>"), nil
				}
				return makeResponse(req, http.StatusForbidden, "Forbidden"), nil
			}

			// Scenario 2: Behavioral Trust for root
			if path == "/" || path == "" {
				if req.Header.Get("X-Forwarded-Host") == "internal-restricted.local" {
					return makeResponse(req, http.StatusOK, "Custom Host Response"), nil
				}
				return makeResponse(req, http.StatusOK, "Normal Response"), nil
			}

			return makeResponse(req, http.StatusNotFound, "Not Found"), nil
		}),
	}

	var findings []core.Finding
	Scan("http://example.com", client, func(f core.Finding) {
		findings = append(findings, f)
	})

	hasBypass := false
	hasBehavioral := false

	for _, f := range findings {
		if f.Type == "Improper Trust in HTTP Headers (Proxy Bypass)" {
			hasBypass = true
		}
		if f.Type == "Improper Trust in HTTP Headers (Behavioral)" {
			hasBehavioral = true
		}
	}

	if !hasBypass {
		t.Fatal("expected Proxy Bypass finding for /admin")
	}
	if !hasBehavioral {
		t.Fatal("expected Behavioral Trust finding for root")
	}
}
