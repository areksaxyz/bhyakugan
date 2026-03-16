package vulns

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/utils"
)

var UploadPaths = []string{
	"/upload", "/api/upload", "/api/v1/upload", "/file/upload", "/v1/upload",
	"/upload.php", "/uploader", "/api/image/upload", "/api/v1/user/avatar",
}

var uploadedFileCandidate = regexp.MustCompile(`(?i)(https?://[^\s"'<>]+|/[^\s"'<>]*(?:bhyakugan_test\.php|upload[^\s"'<>]*|files?[^\s"'<>]*|media[^\s"'<>]*))`)

func ScanFileUpload(baseURL string, client *http.Client, onFound func(core.Finding)) {
	// Simple unauthenticated upload check on common paths
	parts := strings.Split(baseURL, "/")
	if len(parts) < 3 {
		return
	}
	rootURL := parts[0] + "//" + parts[2]

	for _, path := range UploadPaths {
		target := rootURL + path
		testUpload(target, client, onFound)
	}
}

func testUpload(url string, client *http.Client, onFound func(core.Finding)) {
	marker := fmt.Sprintf("BHYAKUGAN_UPLOAD_TEST_%d", time.Now().UnixNano())
	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	// Try to upload a dummy PHP file
	fw, err := w.CreateFormFile("file", "bhyakugan_test.php")
	if err != nil {
		return
	}
	if _, err = io.Copy(fw, strings.NewReader(fmt.Sprintf("<?php echo '%s'; ?>", marker))); err != nil {
		return
	}
	w.Close()

	req, err := http.NewRequest("POST", url, &b)
	if err != nil {
		return
	}

	utils.SetDefaultHeaders(req, url)
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// If 200/201, it might be successful
	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
		bodyStr := string(body)

		if responseLooksLikeUploadSuccess(bodyStr) {
			if verifiedURL, ok := verifyUploadedMarker(extractUploadVerificationTargets(url, resp, bodyStr), marker, client); ok {
				onFound(core.Finding{
					Type:       "Unauthenticated File Upload",
					Target:     verifiedURL,
					Detail:     "Uploaded test file was retrievable without authentication and contained the expected verification marker.",
					Severity:   "High",
					Confidence: "confirmed",
				})
				return
			}

			onFound(core.Finding{
				Type:       "Unauthenticated File Upload",
				Target:     url,
				Detail:     "Endpoint accepted an unauthenticated test upload, but the uploaded file path could not be verified automatically.",
				Severity:   "Medium",
				Confidence: "probable",
			})
		}
	}
}

func responseLooksLikeUploadSuccess(body string) bool {
	bodyLower := strings.ToLower(body)
	return strings.Contains(bodyLower, "success") || strings.Contains(bodyLower, "uploaded") || strings.Contains(bodyLower, "file_name")
}

func extractUploadVerificationTargets(uploadURL string, resp *http.Response, body string) []string {
	seen := make(map[string]bool)
	var out []string

	add := func(raw string) {
		resolved, ok := resolveUploadReference(uploadURL, raw)
		if !ok || seen[resolved] {
			return
		}
		seen[resolved] = true
		out = append(out, resolved)
	}

	if resp != nil {
		add(resp.Header.Get("Location"))
	}

	for _, match := range uploadedFileCandidate.FindAllString(body, -1) {
		add(match)
	}

	return out
}

func resolveUploadReference(baseURL, raw string) (string, bool) {
	ref := strings.TrimSpace(raw)
	if ref == "" {
		return "", false
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return "", false
	}
	parsed, err := url.Parse(ref)
	if err != nil {
		return "", false
	}

	resolved := base.ResolveReference(parsed)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", false
	}
	return resolved.String(), true
}

func verifyUploadedMarker(candidates []string, marker string, client *http.Client) (string, bool) {
	for _, candidate := range candidates {
		req, err := http.NewRequest("GET", candidate, nil)
		if err != nil {
			continue
		}
		utils.SetDefaultHeaders(req, candidate)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 1024*1024), 1024*1024))
		resp.Body.Close()
		if resp.StatusCode == 200 && strings.Contains(string(body), marker) {
			return candidate, true
		}
	}
	return "", false
}
