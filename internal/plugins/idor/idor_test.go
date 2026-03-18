package idor

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
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     h,
		Request:    req,
	}
}

func TestScanEmitsObjectReferenceSurfaceHint(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Query().Get("user_id") {
			case "8":
				return testResponse(req, http.StatusOK, `{"id":8,"name":"alice","plan":"pro"}`), nil
			case "6":
				return testResponse(req, http.StatusOK, `{"id":6,"name":"kate","plan":"team"}`), nil
			default:
				return testResponse(req, http.StatusOK, `{"id":7,"name":"baseline-user","plan":"free"}`), nil
			}
		}),
	}

	var findings []core.Finding
	Scan("https://example.com/api/profile?user_id=7", client, func(f core.Finding) {
		findings = append(findings, f)
	})

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].Type != "Object Reference Surface" {
		t.Fatalf("expected Object Reference Surface type, got %q", findings[0].Type)
	}
	if findings[0].Severity != "Info" {
		t.Fatalf("expected Info severity, got %q", findings[0].Severity)
	}
	if findings[0].Confidence != core.ConfidenceProbable {
		t.Fatalf("expected probable confidence, got %q", findings[0].Confidence)
	}
	if !strings.Contains(strings.ToLower(findings[0].Detail), "authorization-relevant hint") {
		t.Fatalf("expected surface-style detail, got %q", findings[0].Detail)
	}
}
