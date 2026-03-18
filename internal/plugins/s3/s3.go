package s3

import (
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/areksaxyz/bhyakugan/internal/core"
	"github.com/areksaxyz/bhyakugan/internal/payloadrepo"
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

func mergedSensitiveFiles() []string {
	files := []string{"backup.sql", "users.json", "config.json", ".env", "database.yml"}
	seen := make(map[string]bool, len(files))
	for _, file := range files {
		seen[strings.ToLower(file)] = true
	}

	extra := payloadrepo.LoadRepoLines(24,
		"verify/file-interesting-names.txt",
		"file-interesting-names.txt",
	)
	for _, raw := range extra {
		name := strings.TrimSpace(path.Base(raw))
		if name == "." || name == "/" || name == "" || strings.Contains(name, "/") {
			continue
		}
		lower := strings.ToLower(name)
		if seen[lower] {
			continue
		}
		seen[lower] = true
		files = append(files, name)
	}
	return files
}

func listingInterestingKeywordHits(body string) []string {
	keywords := payloadrepo.LoadRepoLines(24,
		"verify/response-interesting-keywords.txt",
		"response-interesting-keywords.txt",
	)
	if len(keywords) == 0 {
		return nil
	}

	bodyLower := strings.ToLower(body)
	seen := map[string]bool{}
	var hits []string
	for _, raw := range keywords {
		keyword := strings.ToLower(strings.TrimSpace(raw))
		if keyword == "" || seen[keyword] || !strings.Contains(bodyLower, keyword) {
			continue
		}
		seen[keyword] = true
		hits = append(hits, keyword)
		if len(hits) >= 6 {
			break
		}
	}
	sort.Strings(hits)
	return hits
}

// Scan performs S3 bucket enumeration based on the domain name
func Scan(domain string, client *http.Client, wg *sync.WaitGroup, onFound func(core.Finding)) {
	if wg != nil {
		defer wg.Done()
	}
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

	sensitiveFiles := mergedSensitiveFiles()

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
			if hits := listingInterestingKeywordHits(bodyStr); len(hits) > 0 {
				detail += fmt.Sprintf(" Listing keywords: %s.", strings.Join(hits, ", "))
			}

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
					Confidence: core.ConfidenceConfirmed,
				})
			} else {
				fmt.Printf("[*] Skipping Cloud Storage bucket with unclear ownership: %s\n", u)
			}
		}
	}
}
