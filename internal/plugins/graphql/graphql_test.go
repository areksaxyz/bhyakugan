package graphql

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
				body, _ := io.ReadAll(io.LimitReader(io.LimitReader(req.Body, 5*1024*1024), 5*1024*1024))
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

func TestIsLikelyGraphQLTargetAcceptsWordlistParams(t *testing.T) {
	restoreGraphQLWordlistsRoot(t)

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("test"), 0644); err != nil {
		t.Fatalf("write README failed: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "discovery"), 0755); err != nil {
		t.Fatalf("mkdir discovery failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "discovery", "graphql-endpoints.txt"), []byte("/gqlx\n"), 0644); err != nil {
		t.Fatalf("write endpoints wordlist failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "discovery", "graphql-params.txt"), []byte("gql_query\n"), 0644); err != nil {
		t.Fatalf("write params wordlist failed: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "verify"), 0755); err != nil {
		t.Fatalf("mkdir verify failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "verify", "graphql-safe-probes.txt"), []byte("application/vnd.graphql+json\n"), 0644); err != nil {
		t.Fatalf("write safe probes wordlist failed: %v", err)
	}
	payloadrepo.SetWordlistsRoot(root)

	if !isLikelyGraphQLTarget("https://example.com/api?gql_query={viewer{id}}", mergedGraphQLEndpoints(), mergedGraphQLParams()) {
		t.Fatal("expected custom GraphQL param wordlist entry to mark target as likely GraphQL")
	}

	allowed := mergedGraphQLContentTypes()
	found := false
	for _, contentType := range allowed {
		if contentType == "application/vnd.graphql+json" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected custom GraphQL content type to be loaded from verify/graphql-safe-probes.txt")
	}
}

func restoreGraphQLWordlistsRoot(t *testing.T) {
	t.Helper()
	original := payloadrepo.WordlistsRoot()
	t.Cleanup(func() {
		if original != "" {
			payloadrepo.SetWordlistsRoot(original)
		}
	})
}
