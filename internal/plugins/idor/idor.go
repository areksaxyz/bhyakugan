package idor

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/yupiyy/bhyakugan/internal/core"
)

var (
	idRegex = regexp.MustCompile(`^[0-9]{1,10}$`)
)

func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return
	}

	q := u.Query()
	if len(q) == 0 {
		return
	}

	for param, values := range q {
		for _, val := range values {
			if idRegex.MatchString(val) {
				checkIDOR(baseURL, param, val, client, onFound)
			}
		}
	}
}

func checkIDOR(baseURL, param, originalVal string, client *http.Client, onFound func(core.Finding)) {
	id, _ := strconv.Atoi(originalVal)
	
	// Try +1 and -1
	testValues := []string{strconv.Itoa(id + 1), strconv.Itoa(id - 1)}
	if id <= 0 {
		testValues = []string{strconv.Itoa(id + 1), strconv.Itoa(id + 2)}
	}

	// 1. Get Baseline
	baseResp, err := client.Get(baseURL)
	if err != nil {
		return
	}
	defer baseResp.Body.Close()
	baseBody, _ := io.ReadAll(baseResp.Body)
	baseBodyStr := string(baseBody)
	baseLen := len(baseBodyStr)

	if baseResp.StatusCode != 200 {
		return
	}

	for _, tVal := range testValues {
		if tVal == "0" && id != 0 {
			continue 
		}

		u, _ := url.Parse(baseURL)
		q := u.Query()
		q.Set(param, tVal)
		u.RawQuery = q.Encode()
		target := u.String()

		resp, err := client.Get(target)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// Heuristic for IDOR in unauthenticated context:
		// 1. Status is 200
		// 2. Length is different but "similar" (e.g. within 20-50% range, not a total error page)
		// 3. Content-Type is likely JSON or contains data markers
		if resp.StatusCode == 200 {
			diff := len(bodyStr) - baseLen
			if diff < 0 {
				diff = -diff
			}

			// If length is exactly the same, it might be the same object or a generic response
			if len(bodyStr) == baseLen && bodyStr == baseBodyStr {
				continue
			}

			// If length is significantly different but not too much (e.g. not a 10x difference which usually means error/redirect)
			if diff > 0 && diff < baseLen/2 {
				// Check if it looks like JSON or structured data
				isData := strings.HasPrefix(strings.TrimSpace(bodyStr), "{") || 
						  strings.HasPrefix(strings.TrimSpace(bodyStr), "[") ||
						  strings.Contains(resp.Header.Get("Content-Type"), "application/json")

				if isData {
					onFound(core.Finding{
						Type:       "Potential IDOR",
						Target:     target,
						Detail:     fmt.Sprintf("Parameter '%s' looks like an ID. Changing it from %s to %s returned a different but valid-looking response (len: %d vs baseline: %d). This may indicate an Insecure Direct Object Reference.", param, originalVal, tVal, len(bodyStr), baseLen),
						Severity:   "Medium",
						Confidence: "probable",
					})
					return // Found for this param
				}
			}
		}
	}
}
