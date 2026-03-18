package websocket

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

func testResponse(req *http.Request, status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     headers,
		Request:    req,
	}
}

func TestCheckHandshakeDefaultSeverityInfo(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return testResponse(req, 101, "", nil), nil
		}),
	}

	var findings []core.Finding
	checkHandshake("http://example.com/ws", client, func(f core.Finding) {
		findings = append(findings, f)
	})

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].Severity != "Info" {
		t.Fatalf("expected severity Info, got %q", findings[0].Severity)
	}
}

func TestCheckHandshakeSessionCookieSeverityLow(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			h := make(http.Header)
			h.Add("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly")
			return testResponse(req, 101, "", h), nil
		}),
	}

	var findings []core.Finding
	checkHandshake("http://example.com/ws", client, func(f core.Finding) {
		findings = append(findings, f)
	})

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].Severity != "Low" {
		t.Fatalf("expected severity Low, got %q", findings[0].Severity)
	}
	if findings[0].Confidence != "probable" {
		t.Fatalf("expected confidence probable, got %q", findings[0].Confidence)
	}
}
