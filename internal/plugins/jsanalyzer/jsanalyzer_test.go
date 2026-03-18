package jsanalyzer

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/areksaxyz/bhyakugan/internal/core"
	"github.com/areksaxyz/bhyakugan/internal/payloadrepo"
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

func TestFindKeywordReferencesUseWordlists(t *testing.T) {
	restoreJSWordlistsRoot(t)

	root := t.TempDir()
	writeWordlistFile(t, root, "README.md", "test")
	writeWordlistFile(t, root, "verify/js-secret-keywords.txt", "firebase\nprivate_key\n")
	writeWordlistFile(t, root, "verify/js-endpoint-keywords.txt", "/internal/\n/swagger\n")
	payloadrepo.SetWordlistsRoot(root)

	references, keywords := findKeywordReferences(`const cfg="/internal/admin/users"; const key="firebaseConfig";`, mergedJSEndpointKeywords())
	if len(references) == 0 || len(keywords) == 0 {
		t.Fatal("expected endpoint keyword references to be extracted from quoted JS literals")
	}

	references, keywords = findKeywordReferences(`const a="firebaseConfig"; const b="private_key_material";`, mergedJSSecretKeywords())
	if len(references) == 0 || len(keywords) == 0 {
		t.Fatal("expected secret keyword references to be extracted from quoted JS literals")
	}
}

func TestProbeEndpointMethodsUsesInterestingResponseKeywords(t *testing.T) {
	restoreJSWordlistsRoot(t)

	root := t.TempDir()
	writeWordlistFile(t, root, "README.md", "test")
	writeWordlistFile(t, root, "verify/response-interesting-keywords.txt", "token\nswagger\n")
	payloadrepo.SetWordlistsRoot(root)

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			headers := make(http.Header)
			headers.Set("Content-Type", "application/json")
			return testResponse(req, http.StatusOK, `{"token":"abc123","message":"ok"}`, headers), nil
		}),
	}

	var findings []core.Finding
	probeEndpointMethods("https://example.com/api/private", client, func(f core.Finding) {
		findings = append(findings, f)
	})

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Detail, "keywords=") {
		t.Fatalf("expected interesting response keyword hits in detail, got %q", findings[0].Detail)
	}
}

func restoreJSWordlistsRoot(t *testing.T) {
	t.Helper()
	original := payloadrepo.WordlistsRoot()
	t.Cleanup(func() {
		if original != "" {
			payloadrepo.SetWordlistsRoot(original)
		}
	})
}

func writeWordlistFile(t *testing.T, root, relPath, content string) {
	t.Helper()
	fullPath := filepath.Join(root, relPath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		t.Fatalf("mkdir %s failed: %v", relPath, err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatalf("write %s failed: %v", relPath, err)
	}
}
