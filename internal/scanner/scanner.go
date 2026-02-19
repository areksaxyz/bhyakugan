package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

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
	"github.com/yupiyy/bhyakugan/internal/plugins/rce"
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
	Target       string
	Timeout      int
	PayloadFile  string
	Depth        int
	SharedJS     *sync.Map
	Mode         string
	Fast         bool
	MaxEndpoints int
}

func profileTarget(urlStr string, client *http.Client) core.ScanContext {
	ctx := core.ScanContext{Language: "unknown", Framework: "unknown", WAF: "none", Baseline: -1}

	var resp *http.Response
	var err error

	// SMART RETRY LOGIC (Max 3 attempts)
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("GET", urlStr, nil)
		utils.SetDefaultHeaders(req, urlStr)
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(time.Duration(i+1) * time.Second)
	}

	if err != nil {
		return ctx
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	ctx.Baseline = len(body)
	bodyStr := strings.ToLower(string(body))

	headers := resp.Header
	server := strings.ToLower(headers.Get("Server"))
	poweredBy := strings.ToLower(headers.Get("X-Powered-By"))
	cookies := strings.Join(headers.Values("Set-Cookie"), " ")

	if strings.Contains(server, "cloudflare") || headers.Get("Cf-Ray") != "" {
		ctx.WAF = "cloudflare"
	} else if strings.Contains(server, "akamai") || strings.Contains(server, "ghost") {
		ctx.WAF = "akamai"
	}

	if strings.Contains(poweredBy, "php") || strings.Contains(cookies, "phpsessid") || strings.Contains(bodyStr, "php") {
		ctx.Language = "php"
		if strings.Contains(cookies, "laravel_session") || strings.Contains(bodyStr, "laravel") {
			ctx.Framework = "laravel"
		}
	} else if strings.Contains(poweredBy, "express") || strings.Contains(cookies, "connect.sid") || strings.Contains(bodyStr, "node.js") {
		ctx.Language = "node"
	} else if strings.Contains(server, "gunicorn") || strings.Contains(cookies, "csrftoken") || strings.Contains(bodyStr, "django") {
		ctx.Language = "python"
		ctx.Framework = "django"
	} else if strings.Contains(poweredBy, "asp.net") || headers.Get("X-Aspnet-Version") != "" {
		ctx.Language = "dotnet"
	}

	return ctx
}

func Start(opts Options, client *http.Client, onFound func(core.Finding)) {
	mode := strings.ToLower(strings.TrimSpace(opts.Mode))
	if mode == "" {
		mode = "strict"
	}
	if mode != "strict" && mode != "balanced" && mode != "aggressive" {
		mode = "strict"
	}

	reportFinding := func(f core.Finding) {
		f.Confidence = classifyConfidence(f)
		if !shouldReportFinding(mode, f) {
			return
		}
		onFound(f)
	}

	scanConcurrency := 30
	crawlConcurrency := 15
	jsConcurrency := 10
	if opts.Fast {
		scanConcurrency = 10
		crawlConcurrency = 5
		jsConcurrency = 4
	}
	scanSem := make(chan struct{}, scanConcurrency)
	crawlSem := make(chan struct{}, crawlConcurrency)
	jsSem := make(chan struct{}, jsConcurrency)
	maxEndpoints := opts.MaxEndpoints
	if maxEndpoints <= 0 && opts.Fast {
		maxEndpoints = 25
	}

	ctx := profileTarget(opts.Target, client)
	if ctx.Baseline == -1 {
		fmt.Printf("[-] Failed to establish baseline for %s after retries. Skipping.\n", opts.Target)
		return
	}
	fmt.Printf("[*] Profile: %s | Lang=%s | WAF=%s\n", opts.Target, ctx.Language, ctx.WAF)

	baselineURL := opts.Target
	if !strings.HasSuffix(baselineURL, "/") {
		baselineURL += "/"
	}
	baselineURL += "bhyakugan_baseline_test_404"

	reqM, _ := http.NewRequest("GET", opts.Target, nil)
	utils.SetDefaultHeaders(reqM, opts.Target)
	respM, errM := client.Do(reqM)

	var mainBody string
	var mainHeaders http.Header
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
			start := time.Now()
			fmt.Printf("[*] [%s] started\n", name)
			f()
			fmt.Printf("[*] [%s] done (%.1fs)\n", name, time.Since(start).Seconds())
		}()
	}

	scannedEndpoints := make(map[string]bool)
	var endpointMu sync.Mutex
	endpointLimitNotified := false

	scanEndpoint := func(url string, isRoot bool) {
		endpointMu.Lock()
		if !isRoot && maxEndpoints > 0 && len(scannedEndpoints) >= maxEndpoints {
			if !endpointLimitNotified {
				fmt.Printf("[*] Endpoint cap reached (%d). Skipping additional endpoints.\n", maxEndpoints)
				endpointLimitNotified = true
			}
			endpointMu.Unlock()
			return
		}
		if scannedEndpoints[url] {
			endpointMu.Unlock()
			return
		}
		scannedEndpoints[url] = true
		endpointMu.Unlock()

		var pWg sync.WaitGroup
		runP := func(f func()) {
			pWg.Add(1)
			go func() {
				defer pWg.Done()
				f()
			}()
		}

		hasParams := strings.Contains(url, "?")
		runP(func() { secrets.Scan(url, client, reportFinding) })

		if !opts.Fast && (isRoot || hasParams) {
			runP(func() { vulns.Scan(url, client, opts.PayloadFile, reportFinding) })
			runP(func() { rce.Scan(url, client, ctx, reportFinding) })
			runP(func() { nosqli.Scan(url, client, ctx, reportFinding) })
			runP(func() { sqli.Scan(url, client, ctx, reportFinding) })
			runP(func() { ssrf.Scan(url, client, reportFinding) })
			runP(func() { ssti.Scan(url, client, reportFinding) })
			runP(func() { xpath.Scan(url, client, reportFinding) })
			runP(func() { xslt.Scan(url, client, reportFinding) })
			runP(func() { pp.Scan(url, client, reportFinding) })
		}

		if !opts.Fast && (isRoot || strings.Contains(strings.ToLower(url), "login") || strings.Contains(strings.ToLower(url), "auth")) {
			runP(func() { wcd.Scan(url, client, reportFinding) })
			runP(func() { typejuggling.Scan(url, client, ctx, reportFinding) })
		}

		if !opts.Fast {
			runP(func() { proxy.Scan(url, client, reportFinding) })
		}

		if isRoot {
			if !opts.Fast {
				runP(func() { saml.Scan(url, client, reportFinding) })
			}
			runP(func() { graphql.Scan(url, client, reportFinding) })
			runP(func() { git.Scan(url, client, reportFinding) })
		}
		pWg.Wait()
	}

	run("Endpoint Scan (Target)", func() { scanEndpoint(opts.Target, true) })
	run("Directories", func() { directories.Scan(opts.Target, client, reportFinding) })
	if !opts.Fast {
		run("WebSocket", func() { websocket.Scan(opts.Target, client, reportFinding) })
		run("ORM Leak", func() { ormleak.Scan(opts.Target, client, reportFinding) })
	}

	if mainBody != "" {
		run("JWT", func() { jwt.Scan(opts.Target, client, mainBody, mainHeaders, reportFinding) })

		wg.Add(1)
		go func() {
			defer wg.Done()
			maxDepth := opts.Depth
			if opts.Fast && maxDepth > 1 {
				maxDepth = 1
			}

			type CrawlJob struct {
				URL   string
				Depth int
			}
			queue := make(chan CrawlJob, 1000)
			visited := make(map[string]bool)
			var visitedMu sync.Mutex

			var scanWg sync.WaitGroup
			var crawlWg sync.WaitGroup

			visitedMu.Lock()
			visited[opts.Target] = true
			visitedMu.Unlock()

			// Start Consumer
			go func() {
				for job := range queue {
					crawlSem <- struct{}{}
					go func(current CrawlJob) {
						defer func() { <-crawlSem }()
						defer crawlWg.Done()

						if current.Depth > 0 {
							lowerURL := strings.ToLower(current.URL)
							isStatic := false
							staticExts := []string{".jpg", ".jpeg", ".png", ".gif", ".svg", ".css", ".pdf", ".woff", ".woff2", ".ttf"}
							for _, ext := range staticExts {
								if strings.HasSuffix(lowerURL, ext) {
									isStatic = true
									break
								}
							}

							if !isStatic {
								scanWg.Add(1)
								go func(l string) {
									defer scanWg.Done()
									scanSem <- struct{}{}
									defer func() { <-scanSem }()
									scanEndpoint(l, false)
								}(current.URL)
							}
						}

						if current.Depth >= maxDepth {
							return
						}

						var extractWg sync.WaitGroup
						var linksMu sync.Mutex
						var extractedLinks []string

						extractWg.Add(1)
						go func() {
							defer extractWg.Done()
							req, _ := http.NewRequest("GET", current.URL, nil)
							utils.SetDefaultHeaders(req, current.URL)
							resp, err := client.Do(req)
							if err == nil {
								body, _ := io.ReadAll(resp.Body)
								resp.Body.Close()
								links := crawler.ExtractLinks(current.URL, string(body))
								linksMu.Lock()
								extractedLinks = append(extractedLinks, links...)
								linksMu.Unlock()
							}
						}()

						extractWg.Add(1)
						go func() {
							defer extractWg.Done()
							mobileUA := "Mozilla/5.0 (iPhone; CPU iPhone OS 15_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Mobile/15E148 Safari/604.1"
							reqMobile, _ := http.NewRequest("GET", current.URL, nil)
							reqMobile.Header.Set("User-Agent", mobileUA)
							respMobile, errMobile := client.Do(reqMobile)
							if errMobile == nil {
								bodyMobile, _ := io.ReadAll(respMobile.Body)
								respMobile.Body.Close()
								mLinks := crawler.ExtractLinks(current.URL, string(bodyMobile))
								linksMu.Lock()
								extractedLinks = append(extractedLinks, mLinks...)
								linksMu.Unlock()
							}
						}()

						extractWg.Wait()

						visitedMu.Lock()
						for _, link := range extractedLinks {
							if !visited[link] {
								visited[link] = true
								if current.Depth+1 <= maxDepth {
									crawlWg.Add(1)
									select {
									case queue <- CrawlJob{URL: link, Depth: current.Depth + 1}:
									default: // Prevent blocking if queue is full
									}
								}
							}
						}
						visitedMu.Unlock()
					}(job)
				}
			}()

			// Start initial job
			crawlWg.Add(1)
			queue <- CrawlJob{URL: opts.Target, Depth: 0}

			// Wait for all crawling to finish, then close queue
			crawlWg.Wait()
			close(queue)

			// Wait for all scans triggered by crawling to finish
			scanWg.Wait()
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			jsRegex := regexp.MustCompile(`src=["'](.*?\.js)["']`)
			matches := jsRegex.FindAllStringSubmatch(mainBody, -1)

			var jsWg sync.WaitGroup
			for _, m := range matches {
				if len(m) > 1 {
					jsURL := m[1]
					if !strings.HasPrefix(jsURL, "http") {
						u, _ := url.Parse(opts.Target)
						jsURL = u.ResolveReference(&url.URL{Path: jsURL}).String()
					}
					if opts.SharedJS != nil {
						if _, loaded := opts.SharedJS.LoadOrStore(jsURL, true); loaded {
							continue
						}
					}

					jsWg.Add(1)
					go func(u string) {
						defer jsWg.Done()
						select {
						case jsSem <- struct{}{}:
							defer func() { <-jsSem }()
							jsanalyzer.ScanJS(u, client, nil, reportFinding) // Pass nil as we handle WaitGroup locally in this goroutine
						case <-time.After(4 * time.Second):
							// Don't wait forever for a slot in jsSem
							return
						}
					}(jsURL)
				}
			}

			// Wait for all JS in this host with a timeout
			done := make(chan struct{})
			go func() {
				jsWg.Wait()
				close(done)
			}()

			jsTimeout := 2 * time.Minute
			if opts.Fast {
				jsTimeout = 45 * time.Second
			}
			select {
			case <-done:
			case <-time.After(jsTimeout):
				fmt.Printf("[!] JS Analysis timeout for %s\n", opts.Target)
			}
		}()
	}
	wg.Wait()
	fmt.Printf("[*] Scan Complete for %s\n", opts.Target)
}

func classifyConfidence(f core.Finding) string {
	if strings.TrimSpace(f.Confidence) != "" {
		return strings.ToLower(strings.TrimSpace(f.Confidence))
	}
	d := strings.ToLower(f.Detail)
	t := strings.ToLower(f.Type)

	if strings.Contains(d, "verification failed") ||
		strings.Contains(d, "unverified") ||
		strings.Contains(d, "invalid") ||
		strings.Contains(d, "potential ") ||
		strings.Contains(d, "no confirmed exploitation") {
		return "noisy"
	}

	if strings.Contains(d, "confirmed") ||
		strings.Contains(d, "verified") ||
		strings.Contains(d, "found output") ||
		strings.Contains(d, "system file read") ||
		strings.Contains(d, "source disclosure") ||
		strings.Contains(d, "introspection query enabled") {
		return "confirmed"
	}

	if strings.Contains(t, "path discovered") ||
		strings.Contains(t, "recon") ||
		strings.Contains(t, "jwt discovered") {
		return "probable"
	}

	return "probable"
}

func shouldReportFinding(mode string, f core.Finding) bool {
	switch mode {
	case "aggressive":
		return true
	case "balanced":
		return f.Confidence != "noisy"
	default: // strict
		if f.Confidence == "noisy" {
			return false
		}
		// Keep strict focused on higher-confidence bug bounty outputs.
		if f.Confidence == "confirmed" {
			return true
		}
		sev := strings.ToLower(f.Severity)
		return sev == "critical" || sev == "high"
	}
}
