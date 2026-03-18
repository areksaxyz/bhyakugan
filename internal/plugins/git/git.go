package git

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/areksaxyz/bhyakugan/internal/core"
	"github.com/areksaxyz/bhyakugan/internal/utils"
)

// Scan checks for exposed .git repositories
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}
	target := baseURL + ".git/HEAD"

	// 1. Check .git/HEAD
	resp, err := client.Get(target)
	if utils.ClassifyError(err) == "refused" {
		return
	}
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	// 2. Verify Content (Must contain 'ref: refs/')
	body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
	bodyStr := string(body)

	if strings.Contains(bodyStr, "ref: refs/") {
		fmt.Printf("[!] CRITICAL: Exposed Git Repository at %s\n", target)

		detail := "Git Repository exposed (.git/HEAD found). Source code likely accessible."

		// 3. Try to extract Remote Origin from config
		configURL := baseURL + ".git/config"
		respConf, errConf := client.Get(configURL)
		if errConf == nil && respConf.StatusCode == 200 {
			confBody, _ := io.ReadAll(io.LimitReader(io.LimitReader(respConf.Body, 5*1024*1024), 5*1024*1024))
			confStr := string(confBody)
			respConf.Body.Close()

			// Regex to find [remote "origin"] url = ...
			re := regexp.MustCompile(`url\s*=\s*(.*)`)
			match := re.FindStringSubmatch(confStr)
			if len(match) > 1 {
				detail += fmt.Sprintf("\nRemote Origin: %s", strings.TrimSpace(match[1]))
			}
		}

		onFound(core.Finding{
			Type:     "Git Exposure",
			Target:   baseURL + ".git/",
			Detail:   detail,
			Severity: "Critical",
		})
	}
}
