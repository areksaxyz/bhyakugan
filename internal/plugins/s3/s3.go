package s3

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/yupiyy/bhyakugan/internal/core"
)

var (
	// Keywords for permutation
	keywords = []string{
		"dev", "prod", "test", "stage", "staging",
		"backup", "backups", "archive", "assets", "static",
		"public", "private", "logs", "data", "db",
		"media", "images", "img", "files", "upload",
		"admin", "secure", "www", "app", "api",
	}
)

// Scan performs S3 bucket enumeration based on the domain name
func Scan(domain string, client *http.Client, wg *sync.WaitGroup, onFound func(core.Finding)) {
	defer wg.Done()
	fmt.Printf("[*] Starting S3 Bucket Enumeration for %s...\n", domain)

	// Clean domain (remove TLD for base name usage, e.g. google.com -> google)
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return
	}
	baseName := parts[0]
	// handle case like co.uk or subdomains
	// A better approach: take the main name. For "sub.example.com", try "sub", "example", "sub-example" etc.
	// For simplicity, let's use the full domain and the first part.

	candidates := make(chan string, 100)

	// Generator
	go func() {
		defer close(candidates)

		// 1. Exact match
		candidates <- baseName
		candidates <- domain
		candidates <- strings.ReplaceAll(domain, ".", "-")

		// 2. Permutations
		for _, kw := range keywords {
			candidates <- fmt.Sprintf("%s-%s", baseName, kw)
			candidates <- fmt.Sprintf("%s-%s", kw, baseName)
			candidates <- fmt.Sprintf("%s.%s", baseName, kw)
			candidates <- fmt.Sprintf("%s.%s", kw, baseName)
			candidates <- fmt.Sprintf("%s%s", baseName, kw)
		}
	}()

	// Worker Pool
	s3Wg := sync.WaitGroup{}
	for i := 0; i < 10; i++ { // 10 Concurrent checks
		s3Wg.Add(1)
		go func() {
			defer s3Wg.Done()
			for name := range candidates {
				checkBucket(name, client, onFound)
			}
		}()
	}
	s3Wg.Wait()
}

func checkBucket(bucketName string, client *http.Client, onFound func(core.Finding)) {
	urls := []string{
		fmt.Sprintf("http://%s.s3.amazonaws.com", bucketName),
		fmt.Sprintf("http://storage.googleapis.com/%s", bucketName),
		fmt.Sprintf("http://%s.blob.core.windows.net/public?restype=container&comp=list", bucketName),
	}

	sensitiveFiles := []string{"backup.sql", "users.json", "config.json", ".env", "database.yml"}

	for _, u := range urls {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
		resp.Body.Close()
		bodyStr := string(body)

		isPublic := false
		if resp.StatusCode == 200 {
			if strings.Contains(u, "amazonaws.com") && strings.Contains(bodyStr, "<ListBucketResult>") {
				isPublic = true
			} else if strings.Contains(u, "googleapis.com") && (strings.Contains(bodyStr, "<?xml") || strings.Contains(bodyStr, "ListBucketResult")) {
				isPublic = true
			} else if strings.Contains(u, "blob.core.windows.net") && strings.Contains(bodyStr, "EnumerationResults") {
				isPublic = true
			}
		}

		if isPublic {
			targetBrand := bucketName
			parts := strings.Split(bucketName, "-")
			if len(parts) > 0 {
				targetBrand = parts[0]
			}

			detail := "Public listable bucket confirmed."
			severity := "High"

			// Check for sensitive files
			var foundFiles []string
			baseURL := u
			if strings.Contains(baseURL, "?") {
				baseURL = strings.Split(baseURL, "?")[0] // Remove query params for direct file access
			}

			for _, f := range sensitiveFiles {
				fileUrl := baseURL + "/" + f

				fResp, fErr := client.Get(fileUrl)
				if fErr == nil {
					fBody, _ := io.ReadAll(io.LimitReader(io.LimitReader(fResp.Body, 5*1024*1024), 5*1024*1024))
					fResp.Body.Close()
					if fResp.StatusCode == 200 && len(fBody) > 0 {
						bodyLower := strings.ToLower(string(fBody))
						if !strings.Contains(bodyLower, "<nosuchkey>") && !strings.Contains(bodyLower, "<error>") {
							foundFiles = append(foundFiles, f)
						}
					}
				}
			}

			if len(foundFiles) > 0 {
				severity = "Critical"
				detail += fmt.Sprintf(" Sensitive files found: %s.", strings.Join(foundFiles, ", "))
			}

			// Report if ownership is clear or if sensitive files were actually found (overriding ownership doubt)
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(targetBrand)) || severity == "Critical" {
				fmt.Printf("[!] POSITIVE MATCH: Public Cloud Storage: %s [%s]\n", u, severity)
				onFound(core.Finding{
					Type:       "Cloud Storage Exposure",
					Target:     baseURL,
					Detail:     detail,
					Severity:   severity,
					Confidence: "confirmed",
				})
			} else {
				fmt.Printf("[*] Skipping Cloud Storage bucket with unclear ownership: %s\n", u)
			}
		}
	}
}
