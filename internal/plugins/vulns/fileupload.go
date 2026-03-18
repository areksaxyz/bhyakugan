package vulns

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/areksaxyz/bhyakugan/internal/core"
	"github.com/areksaxyz/bhyakugan/internal/payloadrepo"
	"github.com/areksaxyz/bhyakugan/internal/utils"
)

var UploadPaths = []string{
	"/upload", "/api/upload", "/api/v1/upload", "/file/upload", "/v1/upload",
	"/upload.php", "/uploader", "/api/image/upload", "/api/v1/user/avatar",
}

var uploadedFileCandidate = regexp.MustCompile(`(?i)(https?://[^\s"'<>]+|/[^\s"'<>]*(?:upload[^\s"'<>]*|files?[^\s"'<>]*|media[^\s"'<>]*|proof[^\s"'<>]*|avatar[^\s"'<>]*|document[^\s"'<>]*|report[^\s"'<>]*|verification[^\s"'<>]*))`)

type uploadProbe struct {
	Filename    string
	ContentType string
}

func ScanFileUpload(baseURL string, client *http.Client, onFound func(core.Finding)) {
	// Simple unauthenticated upload check on common paths
	parts := strings.Split(baseURL, "/")
	if len(parts) < 3 {
		return
	}
	rootURL := parts[0] + "//" + parts[2]

	for _, path := range UploadPaths {
		target := rootURL + path
		for _, probe := range uploadProbesForCurrentMode() {
			testUpload(target, client, probe, onFound)
		}
	}
}

func uploadProbesForCurrentMode() []uploadProbe {
	safeFilenames := payloadrepo.LoadRepoLines(8, "verify/upload-safe-filenames.txt")
	if len(safeFilenames) == 0 {
		safeFilenames = []string{"proof.txt"}
	}

	seen := make(map[string]bool)
	probes := make([]uploadProbe, 0, 2)
	addProbe := func(filename string) {
		filename = strings.TrimSpace(filename)
		if filename == "" || seen[filename] {
			return
		}
		seen[filename] = true
		probes = append(probes, uploadProbe{
			Filename:    filename,
			ContentType: contentTypeForUpload(filename),
		})
	}

	addProbe(safeFilenames[0])

	if payloadrepo.ScanMode() == "aggressive" {
		for _, filename := range payloadrepo.LoadRepoLines(4, "aggressive/upload-bypass-filenames.txt") {
			addProbe(filename)
			if len(probes) >= 3 {
				break
			}
		}
	}

	return probes
}

func contentTypeForUpload(filename string) string {
	allowed := payloadrepo.LoadRepoLines(16, "verify/upload-safe-content-types.txt")
	ext := strings.ToLower(path.Ext(filename))

	preferred := "application/octet-stream"
	switch ext {
	case ".txt", ".log", ".csv":
		preferred = "text/plain"
	case ".png":
		preferred = "image/png"
	case ".jpg", ".jpeg":
		preferred = "image/jpeg"
	case ".pdf":
		preferred = "application/pdf"
	case ".json":
		preferred = "application/json"
	}

	if len(allowed) == 0 {
		return preferred
	}
	for _, candidate := range allowed {
		if strings.EqualFold(candidate, preferred) {
			return candidate
		}
	}
	return allowed[0]
}

func buildUploadBody(filename, marker string) string {
	switch strings.ToLower(path.Ext(filename)) {
	case ".php", ".php3", ".php4", ".php5", ".phtml", ".phar":
		return fmt.Sprintf("<?php echo '%s'; ?>", marker)
	case ".svg":
		return fmt.Sprintf("<svg xmlns=\"http://www.w3.org/2000/svg\"><desc>%s</desc></svg>", marker)
	default:
		return marker
	}
}

func testUpload(url string, client *http.Client, probe uploadProbe, onFound func(core.Finding)) {
	marker := fmt.Sprintf("BHYAKUGAN_UPLOAD_TEST_%d", time.Now().UnixNano())
	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	partHeader := make(textproto.MIMEHeader)
	partHeader.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s"`, probe.Filename))
	partHeader.Set("Content-Type", probe.ContentType)

	fw, err := w.CreatePart(partHeader)
	if err != nil {
		return
	}
	if _, err = io.Copy(fw, strings.NewReader(buildUploadBody(probe.Filename, marker))); err != nil {
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
					Confidence: core.ConfidenceConfirmed,
				})
				return
			}

			onFound(core.Finding{
				Type:       "Unauthenticated File Upload",
				Target:     url,
				Detail:     "Endpoint accepted an unauthenticated test upload, but the uploaded file path could not be verified automatically.",
				Severity:   "Medium",
				Confidence: core.ConfidenceProbable,
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
