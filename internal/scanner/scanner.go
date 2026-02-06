package scanner

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/crawler"
	"github.com/yupiyy/bhyakugan/internal/plugins/directories"
	"github.com/yupiyy/bhyakugan/internal/plugins/git"
	"github.com/yupiyy/bhyakugan/internal/plugins/graphql"
	"github.com/yupiyy/bhyakugan/internal/plugins/jsanalyzer"
	"github.com/yupiyy/bhyakugan/internal/plugins/jwt"
	"github.com/yupiyy/bhyakugan/internal/plugins/nosqli"
	"github.com/yupiyy/bhyakugan/internal/plugins/ormleak"
	"github.com/yupiyy/bhyakugan/internal/plugins/pp"
	"github.com/yupiyy/bhyakugan/internal/plugins/proxy"
	"github.com/yupiyy/bhyakugan/internal/plugins/saml"
	"github.com/yupiyy/bhyakugan/internal/plugins/secrets"
	"github.com/yupiyy/bhyakugan/internal/plugins/sqli"
	"github.com/yupiyy/bhyakugan/internal/plugins/ssrf"
	"github.com/yupiyy/bhyakugan/internal/plugins/ssti"
	"github.com/yupiyy/bhyakugan/internal/plugins/typejuggling"
	"github.com/yupiyy/bhyakugan/internal/plugins/vulns"
	"github.com/yupiyy/bhyakugan/internal/plugins/wcd"
	"github.com/yupiyy/bhyakugan/internal/plugins/websocket"
	"github.com/yupiyy/bhyakugan/internal/plugins/xpath"
	"github.com/yupiyy/bhyakugan/internal/plugins/xslt"
	"github.com/yupiyy/bhyakugan/internal/utils"
)

type Options struct {
	Target      string
	Timeout     int
	PayloadFile string
	Depth       int
}

func Start(opts Options, onFound func(core.Finding)) {
	fmt.Printf("[*] Starting Bhyakugan Scan on %s\n", opts.Target)
	client := utils.NewHttpClient(opts.Timeout)

	baselineURL := opts.Target
	if !strings.HasSuffix(baselineURL, "/") { baselineURL += "/" }
	baselineURL += "bhyakugan_baseline_test_404"
	
	baselineLen := -1
	respB, err := client.Get(baselineURL)
	var mainBody string
	var mainHeaders http.Header
	if err == nil {
		bodyB, _ := io.ReadAll(respB.Body)
		baselineLen = len(bodyB)
		respB.Body.Close()
		fmt.Printf("[*] Baseline for %s established (Len: %d)\n", opts.Target, baselineLen)
	}

	// Fetch Main Page Content
	respM, errM := client.Get(opts.Target)
	
	// Rule 1: Check Connection Refused for Main Target
	if utils.ClassifyError(errM) == "refused" {
		fmt.Printf("[-] Target unreachable (Connection Refused): %s. Aborting scan.\n", opts.Target)
		return
	}

	if errM == nil {
		bodyM, _ := io.ReadAll(respM.Body)
		mainBody = string(bodyM)
		mainHeaders = respM.Header
		respM.Body.Close()
	}

	var wg sync.WaitGroup
	
	run := func(name string, f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f()
		}()
	}

	// Result Collection & Deduplication
	scannedEndpoints := make(map[string]bool)
	var endpointMu sync.Mutex

	// Helper: Scan a specific endpoint with all relevant plugins
	scanEndpoint := func(url string, isRoot bool) {
		endpointMu.Lock()
		if scannedEndpoints[url] {
			endpointMu.Unlock()
			return
		}
		scannedEndpoints[url] = true
		endpointMu.Unlock()

		var pWg sync.WaitGroup
		
		// Run endpoint-specific plugins in PARALLEL
		runP := func(f func()) {
			pWg.Add(1)
			go func() {
				defer pWg.Done()
				f()
			}()
		}

		// 1. Secrets (Response Body Analysis)
		runP(func() { secrets.Scan(url, client, onFound) })
		// 2. Vulnerabilities (LFI, RCE, Custom Payloads)
		runP(func() { vulns.Scan(url, client, opts.PayloadFile, onFound) })
		// 3. Injections
		runP(func() { nosqli.Scan(url, client, onFound) })
		runP(func() { sqli.Scan(url, client, onFound) })
		runP(func() { ssrf.Scan(url, client, onFound) })
		runP(func() { ssti.Scan(url, client, onFound) })
		runP(func() { xpath.Scan(url, client, onFound) })
		runP(func() { xslt.Scan(url, client, onFound) })
		runP(func() { pp.Scan(url, client, onFound) })
		// 4. Logic/Auth
		runP(func() { wcd.Scan(url, client, onFound) })
		// 5. Others
		runP(func() { typejuggling.Scan(url, client, onFound) })
		runP(func() { proxy.Scan(url, client, onFound) })
		
		// Global/Root-only discovery (Don't run on every sub-page to avoid slowness)
		if isRoot {
			runP(func() { saml.Scan(url, client, onFound) })
			runP(func() { graphql.Scan(url, client, onFound) })
			runP(func() { git.Scan(url, client, onFound) })
		}

		pWg.Wait()
	}

	// 1. Scan the Target URL itself
	run("Endpoint Scan (Target)", func() { scanEndpoint(opts.Target, true) })
	
	// 2. Run Domain-Wide / Non-Endpoint Specific Scans
	run("Directories", func() { directories.Scan(opts.Target, client, onFound) })
	run("WebSocket", func() { websocket.Scan(opts.Target, client, onFound) })
	run("ORM Leak", func() { ormleak.Scan(opts.Target, client, onFound) }) // Usually static path check

	if mainBody != "" {
		run("JWT", func() { jwt.Scan(opts.Target, client, mainBody, mainHeaders, onFound) })
		
		// --- RECURSIVE CRAWLER INTEGRATION ---
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			// Configuration
			maxDepth := opts.Depth
			if maxDepth < 1 { maxDepth = 1 } 
			
			// State
			type CrawlJob struct {
				URL   string
				Depth int
			}
			queue := []CrawlJob{{URL: opts.Target, Depth: 0}}
			visited := make(map[string]bool)
			visited[opts.Target] = true
			
			// Scanner Semaphore (Increase concurrency from 5 to 20)
			scanSem := make(chan struct{}, 20)
			var scanWg sync.WaitGroup

			fmt.Printf("[*] Starting Recursive Crawl (Max Depth: %d)...\n", maxDepth)

			for len(queue) > 0 {
				// Dequeue
				current := queue[0]
				queue = queue[1:]

				if current.Depth >= maxDepth {
					continue
				}

				// --- 1. Fetch & Extract (Dual UA) ---
				var extractedLinks []string
				
				// A. Desktop Pass
				resp, err := client.Get(current.URL)
				
				// Rule 1: Skip if refused
				if utils.ClassifyError(err) == "refused" {
					continue
				}

				if err == nil {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					links := crawler.ExtractLinks(current.URL, string(body))
					extractedLinks = append(extractedLinks, links...)
				}

				// B. Mobile Pass
				mobileUA := "Mozilla/5.0 (iPhone; CPU iPhone OS 15_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Mobile/15E148 Safari/604.1"
				reqMobile, _ := http.NewRequest("GET", current.URL, nil)
				reqMobile.Header.Set("User-Agent", mobileUA)
				respMobile, errMobile := client.Do(reqMobile)
				
				// Rule 1: Skip if refused
				if utils.ClassifyError(errMobile) == "refused" {
					// Just skip mobile pass, proceed with desktop links
				} else if errMobile == nil {
					bodyMobile, _ := io.ReadAll(respMobile.Body)
					respMobile.Body.Close()
					mLinks := crawler.ExtractLinks(current.URL, string(bodyMobile))
					
					// Check for Mobile-Only Links
					dLinkSet := make(map[string]bool)
					for _, l := range extractedLinks { dLinkSet[l] = true }
					
					for _, ml := range mLinks {
						if !dLinkSet[ml] {
							fmt.Printf("[!] FOUND Mobile-Specific Endpoint: %s (at depth %d)\n", ml, current.Depth)
							extractedLinks = append(extractedLinks, ml)
							onFound(core.Finding{
								Type:     "Recon: Mobile Endpoint",
								Target:   ml,
								Detail:   fmt.Sprintf("Discovered at depth %d via Mobile UA", current.Depth),
								Severity: "Info",
							})
						}
					}
				}

				// --- 2. Process Found Links ---
				for _, link := range extractedLinks {
					// Clean & Normalize Link
					link = strings.TrimSuffix(link, "/") 
					
					if visited[link] { continue }
					visited[link] = true

					// Enqueue for next depth
					queue = append(queue, CrawlJob{URL: link, Depth: current.Depth + 1})

					// Trigger Scan
					scanWg.Add(1)
					go func(l string) {
						defer scanWg.Done()
						scanSem <- struct{}{}
						defer func() { <-scanSem }()
						
						// Run Full Endpoint Scan on Discovered Link
						scanEndpoint(l, false)

					}(link)
				}
			}
			scanWg.Wait()
			fmt.Println("[*] Recursive Crawl & Scan Finished.")
		}()
		// ---------------------------

		wg.Add(1)
		go func() {
			defer wg.Done()
			jsRegex := regexp.MustCompile(`src=("|')(.*?\.js)("|')`)
			matches := jsRegex.FindAllStringSubmatch(mainBody, -1)
			for _, m := range matches {
				if len(m) > 1 {
					jsURL := m[1]
					if !strings.HasPrefix(jsURL, "http") {
						if strings.HasSuffix(opts.Target, "/") && strings.HasPrefix(jsURL, "/") {
							jsURL = opts.Target + jsURL[1:]
						} else if !strings.HasSuffix(opts.Target, "/") && !strings.HasPrefix(jsURL, "/") {
							jsURL = opts.Target + "/" + jsURL
						} else {
							jsURL = opts.Target + jsURL
						}
					}
					wg.Add(1)
					go jsanalyzer.ScanJS(jsURL, client, &wg, onFound)
				}
			}
		}()
	}

	wg.Wait()
	fmt.Println("[*] Scan Complete.")
}