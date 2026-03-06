package vulns

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/utils"
)

var UploadPaths = []string{
	"/upload", "/api/upload", "/api/v1/upload", "/file/upload", "/v1/upload",
	"/upload.php", "/uploader", "/api/image/upload", "/api/v1/user/avatar",
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
		testUpload(target, client, onFound)
	}
}

func testUpload(url string, client *http.Client, onFound func(core.Finding)) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	
	// Try to upload a dummy PHP file
	fw, err := w.CreateFormFile("file", "bhyakugan_test.php")
	if err != nil {
		return
	}
	if _, err = io.Copy(fw, strings.NewReader("<?php echo 'BHYAKUGAN_UPLOAD_TEST'; ?>")); err != nil {
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
		body, _ := io.ReadAll(resp.Body)
		bodyStr := strings.ToLower(string(body))
		
		// If response indicates success, it's a high signal
		if strings.Contains(bodyStr, "success") || strings.Contains(bodyStr, "uploaded") || strings.Contains(bodyStr, "file_name") {
			onFound(core.Finding{
				Type:       "Unauthenticated File Upload",
				Target:     url,
				Detail:     "Endpoint allows unauthenticated file upload (Tested with .php). Manual verification required for execution.",
				Severity:   "High",
				Confidence: "probable",
			})
		}
	}
}
