package utils

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func makeResponse(status int, location, body string) *http.Response {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/app", nil)
	resp := &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
	if location != "" {
		resp.Header.Set("Location", location)
	}
	return resp
}

func TestIsRedirectAwareIdenticalTrue(t *testing.T) {
	baseBody := []byte(strings.Repeat("a", 402))
	attackBody := []byte(strings.Repeat("b", 402))
	base := BuildResponseFingerprint(makeResponse(http.StatusFound, "/login", string(baseBody)), baseBody)
	attack := BuildResponseFingerprint(makeResponse(http.StatusFound, "/login", string(attackBody)), attackBody)
	if !IsRedirectAwareIdentical(base, attack) {
		t.Fatal("expected identical redirect/login fingerprint to match")
	}
}

func TestIsRedirectAwareIdenticalFalseOnDifferentLocation(t *testing.T) {
	baseBody := []byte(strings.Repeat("a", 402))
	attackBody := []byte(strings.Repeat("b", 402))
	base := BuildResponseFingerprint(makeResponse(http.StatusFound, "/login", string(baseBody)), baseBody)
	attack := BuildResponseFingerprint(makeResponse(http.StatusFound, "/auth/sso", string(attackBody)), attackBody)
	if IsRedirectAwareIdentical(base, attack) {
		t.Fatal("expected different final location to fail redirect identity check")
	}
}

func TestIsAuthGateFingerprint(t *testing.T) {
	fpRedirect := BuildResponseFingerprint(makeResponse(http.StatusFound, "/login", "redirect"), []byte("redirect"))
	if !IsAuthGateFingerprint(fpRedirect, "redirect") {
		t.Fatal("expected login redirect to be auth-gated")
	}

	fpForbidden := BuildResponseFingerprint(makeResponse(http.StatusForbidden, "", "forbidden"), []byte("forbidden"))
	if !IsAuthGateFingerprint(fpForbidden, "forbidden") {
		t.Fatal("expected 403 to be auth-gated")
	}

	fpOK := BuildResponseFingerprint(makeResponse(http.StatusOK, "", "<html><form><input type='password'/>login</form></html>"), []byte("<html><form><input type='password'/>login</form></html>"))
	if !IsAuthGateFingerprint(fpOK, "<html><form><input type='password'/>login</form></html>") {
		t.Fatal("expected login form body to be auth-gated")
	}
}
