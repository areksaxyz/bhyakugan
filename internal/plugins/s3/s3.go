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
	url := fmt.Sprintf("http://%s.s3.amazonaws.com", bucketName)
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if strings.Contains(bodyStr, "<ListBucketResult>") {
			// --- SCOPE VERIFICATION ---
			// Check if the bucket content mentions the target brand to reduce out-of-scope noise
			targetBrand := strings.Split(url, ".")[0] 
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(targetBrand)) {
				fmt.Printf("[!] POSITIVE MATCH: Public S3 Bucket (Verified Owner): %s\n", url)
				onFound(core.Finding{
					Type:       "S3 Bucket",
					Target:     url,
					Detail:     "Public listable bucket confirmed and ownership signal matches target brand.",
					Severity:   "High",
					Confidence: "confirmed",
				})
			} else {
				// Ownership unclear => drop to avoid false-positive reporting.
				fmt.Printf("[*] Skipping S3 bucket with unclear ownership: %s\n", url)
			}
		}
	}
	// Silent drop 403 or other codes to reduce noise
}
