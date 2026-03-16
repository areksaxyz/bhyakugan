package utils

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// NewHttpClient creates a new HTTP client with strict TLS verification.
func NewHttpClient(timeout int) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: false},
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeout) * time.Second,
	}
	return client
}

// IsTLSError returns true for common TLS certificate validation errors.
func IsTLSError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "x509:") ||
		strings.Contains(msg, "certificate") ||
		strings.Contains(msg, "tls:")
}

// InsecureFetch performs a TLS-insecure GET request and returns status/body.
// Use only for fallback validation paths where strict TLS already failed.
func InsecureFetch(target string, timeout time.Duration) (int, string, http.Header, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return 0, "", nil, err
	}
	SetDefaultHeaders(req, target)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
	return resp.StatusCode, string(body), resp.Header, nil
}

// SetDefaultHeaders adds common bug bounty bypass headers to a request
func SetDefaultHeaders(req *http.Request, targetURL string) {
	if req == nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	// Add Origin and Referer based on target
	if u, err := url.Parse(targetURL); err == nil {
		origin := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		req.Header.Set("Origin", origin)
		req.Header.Set("Referer", origin+"/")
	}
}

// ClassifyError categorizes an error into "refused", "timeout", or "other"
func ClassifyError(err error) string {
	if err == nil {
		return "nil"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "connection refused") {
		return "refused"
	}
	if strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded") || os.IsTimeout(err) {
		return "timeout"
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "timeout"
	}
	return "other"
}

// Truncate limits a string to a maximum length
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// InjectPayload replaces the value of a specific query parameter in a URL with a payload.
func InjectPayload(baseURL, param, payload string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	q := u.Query()
	if q.Has(param) {
		q.Set(param, payload)
		u.RawQuery = q.Encode()
		return u.String()
	}

	return ""
}
