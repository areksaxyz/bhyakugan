package utils

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// NewHttpClient creates a new HTTP client with a specified timeout and insecure skip verify
func NewHttpClient(timeout int) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeout) * time.Second,
	}
	return client
}

// SetDefaultHeaders adds common bug bounty bypass headers to a request
func SetDefaultHeaders(req *http.Request, targetURL string) {
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
