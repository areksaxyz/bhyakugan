package vulns

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/areksaxyz/bhyakugan/internal/core"
)

type Payload struct {
	Name    string
	Payload string
	Check   *regexp.Regexp
}

var CommonErrorIndicators = []string{
	"root:x:0:0", "uid=0(root)", "gid=0(root)", // Strict LFI/RCE
	"mysql_fetch_array", "mysql_connect", "pg_connect", // DB Specific
	"ORA-009", "ORA-000", // Oracle
	"Warning: include(", "Warning: require(", // PHP Include specifics
	"Fatal error: require", "Fatal error: include",
}

var GenericPayloads = []Payload{
	{"RCE (Basic)", ";%20id", regexp.MustCompile(`(uid=\d+\([a-zA-Z0-9_-]+\)\s+gid=\d+\()|(uid=0\(root\))`)},
	{"RCE (Unicode)", "＆＆id", regexp.MustCompile(`(uid=\d+\([a-zA-Z0-9_-]+\)\s+gid=\d+\()|(uid=0\(root\))`)},
}

func Scan(baseURL string, client *http.Client, payloadFile string, onFound func(core.Finding)) {
	// 1. Run Advanced LFI Scan (Built-in)
	ScanLFI(baseURL, client, onFound)

	// 2. Run SSI/ESI Scan
	ScanSSI(baseURL, client, onFound)

	// 3. Run Open Redirect Scan
	ScanOpenRedirect(baseURL, client, onFound)

	// 4. Run File Upload Scan
	ScanFileUpload(baseURL, client, onFound)

	// 5. Run Generic Vulnerability Checks (Built-in)
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	for _, p := range GenericPayloads {
		target := baseURL + p.Payload
		checkPayload(target, p, client, onFound)
	}

	// 3. Run Custom Payloads (If provided)
	if payloadFile != "" {
		file, err := os.Open(payloadFile)
		if err != nil {
			fmt.Printf("[-] Error opening payload file: %v\n", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			var target string
			if strings.Contains(line, "{TARGET}") {
				target = strings.ReplaceAll(line, "{TARGET}", baseURL)
			} else {
				target = baseURL + line
			}
			checkCustomPayload(target, line, client, onFound)
		}
	}
}

func checkPayload(url string, p Payload, client *http.Client, onFound func(core.Finding)) {
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
	if err != nil {
		return
	}
	bodyStr := string(body)

	if p.Check.MatchString(bodyStr) {
		fmt.Printf("[!] POSITIVE MATCH: %s at %s\n", p.Name, url)
		onFound(core.Finding{
			Type:     "Vulnerability",
			Target:   url,
			Detail:   fmt.Sprintf("%s detected with payload %s", p.Name, p.Payload),
			Severity: "Critical",
		})
	}
}

func checkCustomPayload(url string, payloadRaw string, client *http.Client, onFound func(core.Finding)) {
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
	if err != nil {
		return
	}
	bodyStr := string(body)

	for _, indicator := range CommonErrorIndicators {
		if strings.Contains(bodyStr, indicator) {
			fmt.Printf("[!] CUSTOM PAYLOAD MATCH: %s (Found: %s)\n", url, indicator)
			onFound(core.Finding{
				Type:     "Custom Vulnerability",
				Target:   url,
				Detail:   fmt.Sprintf("Payload: %s triggered indicator: %s", payloadRaw, indicator),
				Severity: "Critical",
			})
			break
		}
	}
}
