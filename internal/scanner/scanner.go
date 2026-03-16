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
	"github.com/yupiyy/bhyakugan/internal/plugins/idor"
	"github.com/yupiyy/bhyakugan/internal/plugins/jsanalyzer"
	"github.com/yupiyy/bhyakugan/internal/plugins/jwt"
	"github.com/yupiyy/bhyakugan/internal/plugins/nosqli"
	"github.com/yupiyy/bhyakugan/internal/plugins/ormleak"
	"github.com/yupiyy/bhyakugan/internal/plugins/pp"
	"github.com/yupiyy/bhyakugan/internal/plugins/proxy"
	"github.com/yupiyy/bhyakugan/internal/plugins/rce"
	"github.com/yupiyy/bhyakugan/internal/plugins/recon_html"
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
	Target           string
	Timeout          int
	Threads          int
	PayloadFile      string
	Depth            int
	SharedJS         *sync.Map
	Mode             string
	StrictValidation bool
	Fast             bool
	MaxEndpoints     int
}

type CrawlJob struct {
	URL   string
	Depth int
}

func profileTarget(urlStr string, client *http.Client) core.ScanContext {
	ctx := core.ScanContext{Language: "unknown", Framework: "unknown", WAF: "none", Baseline: -1}

	var resp *http.Response
	var err error

	// SMART RETRY LOGIC (Max 3 attempts)
	for i := 0; i < 3; i++ {
		req, errReq := http.NewRequest("GET", urlStr, nil)
		if errReq != nil {
			err = errReq
			continue
		}
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

	body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))

	ctx.Baseline = len(body)
	bodyStr := strings.ToLower(string(body))

	headers := resp.Header
	server := strings.ToLower(headers.Get("Server"))
	poweredBy := strings.ToLower(headers.Get("X-Powered-By"))
	cookies := strings.ToLower(strings.Join(headers.Values("Set-Cookie"), " "))

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
	mode := normalizeMode(opts.Mode)
	deduper := newFindingDeduper()

	reportFinding := func(f core.Finding) {
		f = EnrichFindingForReporting(f)
		processed, ok := EvaluateFindingWithOptions(mode, opts.StrictValidation, f)
		if !ok {
			return
		}
		if !deduper.ShouldEmit(processed) {
			return
		}
		onFound(processed)
	}

	scanConcurrency := opts.Threads
	if scanConcurrency <= 0 {
		scanConcurrency = 30
		if opts.Fast {
			scanConcurrency = 10
		}
	}
	crawlConcurrency := scanConcurrency / 2
	if crawlConcurrency < 1 {
		crawlConcurrency = 1
	}
	jsConcurrency := scanConcurrency / 3
	if jsConcurrency < 1 {
		jsConcurrency = 1
	}

	scanSem := make(chan struct{}, scanConcurrency)
	crawlSem := make(chan struct{}, crawlConcurrency)
	jsSem := make(chan struct{}, jsConcurrency)
	followupSem := make(chan struct{}, crawlConcurrency)
	maxEndpoints := opts.MaxEndpoints
	if maxEndpoints <= 0 {
		maxEndpoints = defaultMaxEndpoints(mode, opts.Fast)
	}

	var scanEndpoint func(string, bool)

	scheduleFollowupScan := func(target string) {
		if strings.TrimSpace(target) == "" {
			return
		}

		select {
		case followupSem <- struct{}{}:
			defer func() { <-followupSem }()
			scanEndpoint(target, false)
		default:
			fmt.Printf("[*] Follow-up scan queue saturated. Skipping %s\n", target)
		}
	}

	// Wrap reportFinding to auto-scan newly discovered paths
	wrappedReportFinding := func(f core.Finding) {
		reportFinding(f)
		if f.Type == "Path Discovered" || f.Type == "Sensitive Config/Backup Exposed" {
			scheduleFollowupScan(f.Target)
		}
	}

	ctx := profileTarget(opts.Target, client)
	if ctx.Baseline == -1 {
		if strings.HasSuffix(strings.ToLower(opts.Target), ".js") {
			fmt.Printf("[*] Target is a JS file. Running JS Analyzer only.\n")
			jsanalyzer.ScanJS(opts.Target, client, nil, wrappedReportFinding)
			return
		}
		fmt.Printf("[-] Failed to establish baseline for %s. Running fallback scan.\n", opts.Target)
	} else {
		fmt.Printf("[*] Profile: %s | Lang=%s | WAF=%s\n", opts.Target, ctx.Language, ctx.WAF)
	}

	scannedEndpoints := make(map[string]bool)
	var endpointMu sync.Mutex
	endpointLimitNotified := false

	scanEndpoint = func(url string, isRoot bool) {
		endpointMu.Lock()
		allowed, notifyLimit := registerEndpointScan(scannedEndpoints, url, isRoot, maxEndpoints, &endpointLimitNotified)
		if notifyLimit {
			fmt.Printf("[*] Endpoint cap reached (%d). Skipping additional endpoints.\n", maxEndpoints)
		}
		if !allowed {
			endpointMu.Unlock()
			return
		}
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
		runP(func() { secrets.Scan(url, client, wrappedReportFinding) })

		if !opts.Fast && (isRoot || hasParams) {
			runP(func() { vulns.Scan(url, client, opts.PayloadFile, reportFinding) }) // vulns.Scan takes reportFinding
			runP(func() { rce.Scan(url, client, ctx, wrappedReportFinding) })
			runP(func() { nosqli.Scan(url, client, ctx, wrappedReportFinding) })
			runP(func() { sqli.Scan(url, client, ctx, wrappedReportFinding) })
			runP(func() { ssrf.Scan(url, client, wrappedReportFinding) })
			runP(func() { ssti.Scan(url, client, wrappedReportFinding) })
			runP(func() { idor.Scan(url, client, wrappedReportFinding) })
			runP(func() { xpath.Scan(url, client, wrappedReportFinding) })
			runP(func() { xslt.Scan(url, client, wrappedReportFinding) })
			runP(func() { pp.Scan(url, client, wrappedReportFinding) })
		}

		if !opts.Fast && (isRoot || strings.Contains(strings.ToLower(url), "login") || strings.Contains(strings.ToLower(url), "auth")) {
			runP(func() { wcd.Scan(url, client, wrappedReportFinding) })
			runP(func() { typejuggling.Scan(url, client, ctx, wrappedReportFinding) })
		}

		if !opts.Fast {
			runP(func() { proxy.Scan(url, client, wrappedReportFinding) })
		}

		if isRoot {
			if !opts.Fast {
				runP(func() { saml.Scan(url, client, wrappedReportFinding) })
			}
			runP(func() { graphql.Scan(url, client, wrappedReportFinding) })
			runP(func() { git.Scan(url, client, wrappedReportFinding) })
		}
		pWg.Wait()
	}

	reqM, errReqM := http.NewRequest("GET", opts.Target, nil)
	var respM *http.Response
	var errM error
	if errReqM == nil {
		utils.SetDefaultHeaders(reqM, opts.Target)
		respM, errM = client.Do(reqM)
	} else {
		errM = errReqM
	}

	var mainBody string
	var mainHeaders http.Header
	if errM == nil && respM != nil {
		bodyM, _ := io.ReadAll(io.LimitReader(io.LimitReader(respM.Body, 5*1024*1024), 5*1024*1024))
		mainBody = string(bodyM)
		mainHeaders = respM.Header
		respM.Body.Close()
		recon_html.Scan(opts.Target, mainBody, wrappedReportFinding)
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

	run("Endpoint Scan (Target)", func() { scanEndpoint(opts.Target, true) })
	run("Directories", func() { directories.Scan(opts.Target, client, wrappedReportFinding) })
	if !opts.Fast {
		run("WebSocket", func() { websocket.Scan(opts.Target, client, wrappedReportFinding) })
		run("ORM Leak", func() { ormleak.Scan(opts.Target, client, wrappedReportFinding) })
	}

	if mainBody != "" {
		run("JWT", func() { jwt.Scan(opts.Target, client, mainBody, mainHeaders, wrappedReportFinding) })

		wg.Add(1)
		go func() {
			defer wg.Done()
			maxDepth := opts.Depth
			if opts.Fast && maxDepth > 1 {
				maxDepth = 1
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
							if !isLikelyStaticAssetURL(current.URL) {
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
							req, err := http.NewRequest("GET", current.URL, nil)
							if err != nil {
								return
							}
							utils.SetDefaultHeaders(req, current.URL)
							resp, err := client.Do(req)
							if err == nil {
								body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
								bodyStr := string(body)
								resp.Body.Close()
								recon_html.Scan(current.URL, bodyStr, wrappedReportFinding)
								links := crawler.ExtractLinks(current.URL, bodyStr)
								linksMu.Lock()
								extractedLinks = append(extractedLinks, links...)
								linksMu.Unlock()
							}
						}()

						extractWg.Add(1)
						go func() {
							defer extractWg.Done()
							mobileUA := "Mozilla/5.0 (iPhone; CPU iPhone OS 15_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Mobile/15E148 Safari/604.1"
							reqMobile, err := http.NewRequest("GET", current.URL, nil)
							if err != nil {
								return
							}
							reqMobile.Header.Set("User-Agent", mobileUA)
							respMobile, errMobile := client.Do(reqMobile)
							if errMobile == nil {
								bodyMobile, _ := io.ReadAll(io.LimitReader(io.LimitReader(respMobile.Body, 5*1024*1024), 5*1024*1024))
								bodyMobileStr := string(bodyMobile)
								respMobile.Body.Close()
								recon_html.Scan(current.URL, bodyMobileStr, wrappedReportFinding)
								mLinks := crawler.ExtractLinks(current.URL, bodyMobileStr)
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
									enqueueCrawlJob(queue, CrawlJob{URL: link, Depth: current.Depth + 1}, &crawlWg)
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
							jsanalyzer.ScanJS(u, client, nil, wrappedReportFinding) // Pass nil as we handle WaitGroup locally in this goroutine
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

func defaultMaxEndpoints(mode string, fast bool) int {
	if fast {
		return 25
	}

	switch normalizeMode(mode) {
	case "aggressive":
		return 150
	case "balanced":
		return 100
	default:
		return 75
	}
}

func enqueueCrawlJob(queue chan<- CrawlJob, job CrawlJob, crawlWg *sync.WaitGroup) bool {
	crawlWg.Add(1)
	select {
	case queue <- job:
		return true
	default:
		crawlWg.Done()
		return false
	}
}

func registerEndpointScan(scannedEndpoints map[string]bool, url string, isRoot bool, maxEndpoints int, endpointLimitNotified *bool) (bool, bool) {
	if scannedEndpoints[url] {
		return false, false
	}
	if !isRoot && maxEndpoints > 0 && len(scannedEndpoints) >= maxEndpoints {
		if !*endpointLimitNotified {
			*endpointLimitNotified = true
			return false, true
		}
		return false, false
	}
	scannedEndpoints[url] = true
	return true, false
}

func classifyConfidence(f core.Finding) string {
	quality, explicitQuality := deriveEvidenceQuality(f)
	baseConfidence := "probable"
	if strings.TrimSpace(f.Confidence) != "" {
		baseConfidence = strings.ToLower(strings.TrimSpace(f.Confidence))
		return syncConfidenceWithEvidence(baseConfidence, quality, explicitQuality)
	}
	d := strings.ToLower(f.Detail)
	t := strings.ToLower(f.Type)

	if strings.Contains(d, "verification failed") ||
		strings.Contains(d, "unverified") ||
		strings.Contains(d, "invalid") ||
		strings.Contains(d, "potential ") ||
		strings.Contains(d, "no confirmed exploitation") {
		baseConfidence = "noisy"
		return syncConfidenceWithEvidence(baseConfidence, quality, explicitQuality)
	}

	if strings.Contains(d, "confirmed") ||
		strings.Contains(d, "verified") ||
		strings.Contains(d, "found output") ||
		strings.Contains(d, "system file read") ||
		strings.Contains(d, "source disclosure") ||
		strings.Contains(d, "sensitive data leak") ||
		strings.Contains(d, "introspection query enabled") {
		baseConfidence = "confirmed"
		return syncConfidenceWithEvidence(baseConfidence, quality, explicitQuality)
	}

	if strings.Contains(t, "path discovered") ||
		strings.Contains(t, "recon") ||
		strings.Contains(t, "jwt discovered") {
		baseConfidence = "probable"
		return syncConfidenceWithEvidence(baseConfidence, quality, explicitQuality)
	}

	return syncConfidenceWithEvidence(baseConfidence, quality, explicitQuality)
}

func normalizeMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return "strict"
	}
	if mode == "bounty" {
		return "strict"
	}
	if mode == "lab" {
		return "aggressive"
	}
	if mode != "strict" && mode != "balanced" && mode != "aggressive" {
		return "strict"
	}
	return mode
}

// EvaluateFinding normalizes confidence and applies mode filtering.
func EvaluateFinding(mode string, f core.Finding) (core.Finding, bool) {
	return EvaluateFindingWithOptions(mode, false, f)
}

// EvaluateFindingWithOptions normalizes confidence and applies mode + validation filtering.
func EvaluateFindingWithOptions(mode string, strictValidation bool, f core.Finding) (core.Finding, bool) {
	mode = normalizeMode(mode)
	f.Confidence = classifyConfidence(f)
	f.Severity = normalizeSeverity(f)
	if !shouldReportFinding(mode, strictValidation, f) {
		return f, false
	}
	return f, true
}

func normalizeSeverity(f core.Finding) string {
	sev := normalizeSeverityLabel(f.Severity)
	conf := strings.ToLower(strings.TrimSpace(f.Confidence))
	t := strings.ToLower(strings.TrimSpace(f.Type))
	quality, explicitQuality := deriveEvidenceQuality(f)

	// Confidence-aware downgrade to reduce inflated "critical" labels.
	if conf == "noisy" {
		switch sev {
		case "Critical":
			sev = "Medium"
		case "High":
			sev = "Low"
		}
	}
	if conf == "probable" && sev == "Critical" {
		sev = "High"
	}
	if conf != "confirmed" {
		if t == "vulnerability" || strings.Contains(t, "custom vulnerability") {
			if sev == "Critical" {
				sev = "High"
			} else if sev == "High" {
				sev = "Medium"
			}
		}
	}

	// Type-specific caps when impact chain is not explicitly confirmed.
	if conf != "confirmed" {
		if strings.Contains(t, "saml vulnerability") && sev == "Critical" {
			sev = "High"
		}
		if strings.Contains(t, "prototype pollution") && sev == "Critical" {
			sev = "High"
		}
		if strings.Contains(t, "server-side template injection") && sev == "Critical" {
			sev = "High"
		}
	}

	sev = applyEvidenceSeverityCaps(f, sev, conf, quality, explicitQuality)
	return normalizeSeverityLabel(sev)
}

func syncConfidenceWithEvidence(confidence string, quality evidenceQuality, explicitQuality bool) string {
	conf := strings.ToLower(strings.TrimSpace(confidence))
	if conf == "" {
		conf = "probable"
	}

	// Noise suppression rule: weak heuristic-only evidence cannot be medium/high confidence.
	if explicitQuality && quality.Score < 40 && !quality.Deterministic && !quality.ControlValidated {
		return "noisy"
	}

	if explicitQuality && quality.Tier == "tier1" && quality.Score >= 80 && conf != "confirmed" {
		return "confirmed"
	}

	if explicitQuality && quality.FPRisk == "very-high" && conf == "confirmed" && quality.Score < 80 {
		return "probable"
	}

	if explicitQuality && quality.Score < 70 && conf == "confirmed" {
		return "probable"
	}

	return conf
}

func applyEvidenceSeverityCaps(f core.Finding, sev, confidence string, quality evidenceQuality, explicitQuality bool) string {
	normalized := normalizeSeverityLabel(sev)
	conf := strings.ToLower(strings.TrimSpace(confidence))
	deterministicExploitProof := hasDeterministicExploitProof(f, quality)
	fType := strings.ToLower(strings.TrimSpace(f.Type))
	detail := strings.ToLower(strings.TrimSpace(f.Detail))

	if !explicitQuality {
		normalized = applyProofDepthSeverityCaps(fType, detail, normalized)
		if deterministicExploitProof && severityRank(normalized) < severityRank("High") {
			return "High"
		}
		return normalizeSeverityLabel(normalized)
	}

	// Hard suppression for low-quality heuristic-only signals.
	if quality.Score < 40 && !quality.Deterministic && !quality.ControlValidated {
		return "Info"
	}

	// Class-specific hardening for historically noisy classes.
	normalized = applyProofDepthSeverityCaps(fType, detail, normalized)
	depth := exploitDepthForSeverity(f)
	normalized = applyExploitDepthCaps(depth, normalized)

	// Deterministic exploit proofs must not stay in low/medium buckets.
	if deterministicExploitProof && severityRank(normalized) < severityRank("High") {
		normalized = "High"
	}

	// Severity-confidence synchronization guardrails.
	if normalized == "Critical" {
		if conf != "confirmed" || quality.Score < 85 || quality.Tier != "tier1" || !quality.Deterministic || !quality.ControlValidated {
			normalized = "High"
		}
	}
	if normalized == "High" {
		if quality.Score < 75 || quality.Tier == "tier3" || !quality.Deterministic || !quality.ControlValidated {
			normalized = "Medium"
		}
	}

	// Severity must follow evidence tiers.
	switch quality.Tier {
	case "tier3":
		switch normalized {
		case "Critical":
			normalized = "Medium"
		case "High":
			normalized = "Low"
		case "Medium":
			normalized = "Low"
		}
	case "tier2":
		if normalized == "Critical" {
			normalized = "High"
		}
	}

	// FP risk caps.
	if !deterministicExploitProof {
		switch quality.FPRisk {
		case "very-high":
			switch normalized {
			case "Critical", "High", "Medium":
				normalized = "Low"
			}
		case "high":
			if normalized == "Critical" {
				normalized = "Medium"
			}
		}
	}

	// Score-based caps.
	if quality.Score < 70 && normalized == "Critical" {
		normalized = "High"
	}
	if quality.Score < 55 {
		if normalized == "High" {
			normalized = "Medium"
		}
		if normalized == "Medium" && conf == "noisy" {
			normalized = "Low"
		}
	}

	if conf == "noisy" && (normalized == "Critical" || normalized == "High") {
		normalized = "Low"
	}
	if deterministicExploitProof && severityRank(normalized) < severityRank("High") {
		normalized = "High"
	}
	return normalizeSeverityLabel(normalized)
}

func exploitDepthForSeverity(f core.Finding) int {
	if depth, ok := ExtractExploitDepth(f.Detail); ok {
		return depth
	}
	fType := strings.ToLower(strings.TrimSpace(f.Type))
	detail := strings.ToLower(strings.TrimSpace(f.Detail))
	switch {
	case strings.Contains(fType, "remote code execution"),
		strings.Contains(detail, "rce confirmed"),
		strings.Contains(detail, "uid=0("):
		return 5
	case strings.Contains(fType, "improper trust in http headers") && strings.Contains(detail, "confirmed bypass: yes"):
		return 4
	case strings.Contains(detail, "root:x:0:0:"),
		strings.Contains(detail, "app_key"),
		strings.Contains(detail, "security-credentials"):
		return 4
	case strings.Contains(detail, "boolean true/false differential confirmed"),
		strings.Contains(detail, "count() differential confirmed"),
		strings.Contains(detail, "payload a (true)") && strings.Contains(detail, "payload b (false)"):
		return 3
	case strings.Contains(detail, "behavioral indicator changed"),
		strings.Contains(detail, "heuristic only"),
		strings.Contains(detail, "signal only"):
		return 1
	case strings.Contains(detail, "error-based sql signal"),
		strings.Contains(detail, "time-based sqli signal"),
		strings.Contains(detail, "xpath error found"):
		return 2
	default:
		return 2
	}
}

func applyExploitDepthCaps(depth int, current string) string {
	normalized := normalizeSeverityLabel(current)
	switch {
	case depth <= 1:
		if severityRank(normalized) > severityRank("Low") {
			return "Low"
		}
	case depth == 2:
		if severityRank(normalized) > severityRank("Medium") {
			return "Medium"
		}
	case depth == 3:
		if severityRank(normalized) > severityRank("High") {
			return "High"
		}
	}
	return normalized
}

func applyProofDepthSeverityCaps(fType, detail, current string) string {
	normalized := normalizeSeverityLabel(current)

	// XPath heuristic signals must not escalate.
	if strings.Contains(fType, "xpath injection") {
		if isXPathHeuristicOnly(detail) {
			return "Info"
		}
		// Error-only deterministic proof is still not equivalent to exploit chain.
		if isXPathErrorOnly(detail) && severityRank(normalized) > severityRank("Medium") {
			return "Medium"
		}
	}

	// Error-only SQLi is a signal, not full exploit chain.
	if (strings.Contains(fType, "sql injection") || strings.Contains(fType, "oracle sqli")) &&
		isSQLErrorOnly(detail) && severityRank(normalized) > severityRank("Medium") {
		return "Medium"
	}

	// SSRF metadata-only fingerprints remain informational without external callback proof.
	if strings.Contains(fType, "ssrf injection") &&
		(strings.Contains(detail, "metadata fingerprint observed") || strings.Contains(detail, "external_callback_validation=false")) {
		if severityRank(normalized) > severityRank("Medium") {
			return "Medium"
		}
		return normalized
	}

	return normalized
}

func isXPathHeuristicOnly(detail string) bool {
	if strings.Contains(detail, "behavioral indicator changed") || strings.Contains(detail, "heuristic only") {
		if strings.Contains(detail, "boolean true/false differential confirmed") ||
			strings.Contains(detail, "count() differential confirmed") ||
			strings.Contains(detail, "structural xml leak detected") ||
			strings.Contains(detail, "xpath error found") {
			return false
		}
		return true
	}
	return strings.Contains(detail, "validation status: informational signal only")
}

func isXPathErrorOnly(detail string) bool {
	if !strings.Contains(detail, "xpath error found") {
		return false
	}
	return !strings.Contains(detail, "boolean true/false differential confirmed") &&
		!strings.Contains(detail, "count() differential confirmed") &&
		!strings.Contains(detail, "structural xml leak detected")
}

func isSQLErrorOnly(detail string) bool {
	errorMarkers := []string{
		"found mysql error",
		"found postgresql error",
		"found mssql error",
		"found oracle error",
		"error-based sql",
	}
	hasError := false
	for _, m := range errorMarkers {
		if strings.Contains(detail, m) {
			hasError = true
			break
		}
	}
	if !hasError {
		return false
	}

	strongProofMarkers := []string{
		"payload a (true)",
		"payload b (false)",
		"boolean-based sql injection confirmed",
		"time-based sqli signal",
		"union select",
		"exfiltration",
		"data extraction",
		"dumped",
	}
	for _, m := range strongProofMarkers {
		if strings.Contains(detail, m) {
			return false
		}
	}
	return true
}

func hasDeterministicExploitProof(f core.Finding, quality evidenceQuality) bool {
	if !quality.Deterministic || !quality.ControlValidated {
		return false
	}
	fType := strings.ToLower(strings.TrimSpace(f.Type))
	detail := strings.ToLower(strings.TrimSpace(f.Detail))

	oracleBooleanProof := (strings.Contains(fType, "oracle sqli") || strings.Contains(fType, "sql injection")) &&
		strings.Contains(detail, "payload a (true)") &&
		strings.Contains(detail, "payload b (false)") &&
		(strings.Contains(detail, "oracle") || strings.Contains(detail, "ora-")) &&
		(strings.Contains(detail, "boolean-based sql injection confirmed") || (strings.Contains(detail, "http 200") && strings.Contains(detail, "http 500")))

	headerTrustBypassProof := strings.Contains(fType, "improper trust in http headers") &&
		strings.Contains(detail, "confirmed bypass: yes") &&
		(strings.Contains(detail, "sensitive-content") ||
			strings.Contains(detail, "admin") ||
			strings.Contains(detail, "config") ||
			strings.Contains(detail, "root"))

	return oracleBooleanProof || headerTrustBypassProof
}

func severityRank(sev string) int {
	switch normalizeSeverityLabel(sev) {
	case "Critical":
		return 5
	case "High":
		return 4
	case "Medium":
		return 3
	case "Low":
		return 2
	default:
		return 1
	}
}

func normalizeSeverityLabel(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Info"
	}
}

func shouldReportFinding(mode string, strictValidation bool, f core.Finding) bool {
	if strictValidation && !passesStrictValidation(f) {
		return false
	}
	conf := strings.ToLower(strings.TrimSpace(f.Confidence))
	switch mode {
	case "aggressive":
		return true
	case "balanced":
		return conf != "noisy"
	default: // strict
		// In strict mode, only keep high-impact findings that are explicitly confirmed.
		if conf != "confirmed" {
			return false
		}
		sev := strings.ToLower(f.Severity)
		return sev == "critical" || sev == "high"
	}
}

func isLikelyStaticAssetURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	lowerPath := strings.ToLower(strings.TrimSpace(u.Path))
	if lowerPath == "" {
		return false
	}
	staticExts := []string{
		".jpg", ".jpeg", ".png", ".gif", ".svg", ".css", ".pdf",
		".woff", ".woff2", ".ttf", ".eot", ".ico", ".js", ".mjs", ".map",
		".webp", ".mp4", ".webm", ".mp3", ".wav",
	}
	for _, ext := range staticExts {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	return false
}

func passesStrictValidation(f core.Finding) bool {
	conf := strings.ToLower(strings.TrimSpace(f.Confidence))
	if conf != "confirmed" {
		return false
	}

	detail := strings.ToLower(strings.TrimSpace(f.Detail))
	fType := strings.ToLower(strings.TrimSpace(f.Type))
	weakSignals := []string{
		"heuristic",
		"probable",
		"no proof",
		"no confirmed exploitation",
		"potential ",
	}
	for _, marker := range weakSignals {
		if strings.Contains(detail, marker) {
			return false
		}
	}

	// Extra-proof requirements for classes that are frequently over-reported.
	if strings.Contains(fType, "saml vulnerability") {
		return strings.Contains(detail, "control-test:passed")
	}
	if strings.Contains(fType, "cross-site websocket hijacking") {
		return strings.Contains(detail, "session-auth-confirmed")
	}
	return true
}
