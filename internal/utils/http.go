package utils

import (
	"crypto/tls"
	"net/http"
	"time"
	"strings"
	"net"
	"os"
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
	return &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeout) * time.Second,
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
