package graphql

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

func TestCheckIntrospectionSeverityInfo(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method == http.MethodPost {
				body, _ := io.ReadAll(req.Body)
				if strings.Contains(string(body), "IntrospectionQuery") {
					return testResponse(req, http.StatusOK, `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`), nil
				}
			}
			return testResponse(req, http.StatusOK, "{}"), nil
		}),
	}

	var findings []core.Finding
	checkIntrospection("http://example.com/graphql", client, func(f core.Finding) {
		findings = append(findings, f)
	})

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != "Info" {
		t.Fatalf("expected severity Info, got %q", f.Severity)
	}
	if f.Confidence != "probable" {
		t.Fatalf("expected confidence probable, got %q", f.Confidence)
	}
}
