package utils

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ResponseFingerprint captures routing/auth behavior used to suppress false positives.
type ResponseFingerprint struct {
	StatusCode    int
	BodySize      int
	FinalLocation string
	RedirectChain string
}

// BuildResponseFingerprint extracts comparable response metadata.
func BuildResponseFingerprint(resp *http.Response, body []byte) ResponseFingerprint {
	fp := ResponseFingerprint{
		BodySize: len(body),
	}
	if resp == nil {
		return fp
	}
	fp.StatusCode = resp.StatusCode
	fp.RedirectChain = redirectChainSignature(resp)

	if loc := canonicalLocation(resp.Header.Get("Location")); loc != "" {
		fp.FinalLocation = loc
	} else if resp.Request != nil && resp.Request.URL != nil {
		fp.FinalLocation = canonicalLocation(resp.Request.URL.String())
	}
	return fp
}

// IsRedirectAwareIdentical returns true when baseline and attack behavior are the same redirect/login flow.
func IsRedirectAwareIdentical(base, attack ResponseFingerprint) bool {
	if base.RedirectChain == "" || attack.RedirectChain == "" {
		return false
	}
	if base.RedirectChain != attack.RedirectChain {
		return false
	}
	if base.FinalLocation == "" || attack.FinalLocation == "" || base.FinalLocation != attack.FinalLocation {
		return false
	}
	return base.BodySize == attack.BodySize
}

// IsAuthGateFingerprint detects common unauthenticated gate behavior.
func IsAuthGateFingerprint(fp ResponseFingerprint, bodyLower string) bool {
	if fp.StatusCode == http.StatusUnauthorized || fp.StatusCode == http.StatusForbidden {
		return true
	}
	if isRedirectStatus(fp.StatusCode) && isLikelyAuthLocation(fp.FinalLocation) {
		return true
	}
	if fp.RedirectChain != "" && isLikelyAuthLocation(fp.FinalLocation) {
		return true
	}
	if fp.StatusCode == http.StatusOK && hasLoginBody(bodyLower) {
		return true
	}
	return false
}

func redirectChainSignature(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	parts := make([]string, 0, 4)
	for current := resp; current != nil; {
		if isRedirectStatus(current.StatusCode) {
			loc := canonicalLocation(current.Header.Get("Location"))
			parts = append(parts, fmt.Sprintf("%d>%s", current.StatusCode, loc))
		}
		if current.Request == nil {
			break
		}
		current = current.Request.Response
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "|")
}

func canonicalLocation(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return strings.ToLower(raw)
	}
	u.Fragment = ""
	host := strings.ToLower(strings.TrimSpace(u.Host))
	pathPart := strings.TrimSpace(u.EscapedPath())
	if pathPart == "" {
		pathPart = "/"
	}
	query := strings.ToLower(strings.TrimSpace(u.RawQuery))

	if host != "" {
		if query != "" {
			return host + pathPart + "?" + query
		}
		return host + pathPart
	}
	if query != "" {
		return pathPart + "?" + query
	}
	return pathPart
}

func isRedirectStatus(status int) bool {
	return status == http.StatusMovedPermanently ||
		status == http.StatusFound ||
		status == http.StatusSeeOther ||
		status == http.StatusTemporaryRedirect ||
		status == http.StatusPermanentRedirect
}

func isLikelyAuthLocation(loc string) bool {
	l := strings.ToLower(strings.TrimSpace(loc))
	if l == "" {
		return false
	}
	markers := []string{
		"/login", "signin", "sign-in", "/auth", "sso", "oauth", "/session", "/account/login",
	}
	for _, marker := range markers {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}

func hasLoginBody(bodyLower string) bool {
	if bodyLower == "" {
		return false
	}
	hasForm := strings.Contains(bodyLower, "<form")
	hasPassword := strings.Contains(bodyLower, "password")
	hasAuthText := strings.Contains(bodyLower, "login") || strings.Contains(bodyLower, "sign in")
	return hasForm && hasPassword && hasAuthText
}
