package vulns

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/areksaxyz/bhyakugan/internal/core"
	"github.com/areksaxyz/bhyakugan/internal/payloadrepo"
	"github.com/areksaxyz/bhyakugan/internal/utils"
)

var OpenRedirectParams = []string{
	"url", "next", "target", "redir", "redirect", "redirect_uri", "redirect_url",
	"dest", "destination", "rurl", "go", "return", "return_to", "to", "checkout_url",
	"image_url", "imageURL", "path", "continue", "page",
}

var OpenRedirectPayloads = []string{
	"//google.com/%2f..",
	"https://google.com/%2f..",
	"/%2f/google.com",
}

func mergedOpenRedirectParams() []string {
	params := append([]string{}, OpenRedirectParams...)
	seen := make(map[string]bool, len(params))
	for _, param := range params {
		seen[strings.ToLower(param)] = true
	}

	extra := payloadrepo.LoadRepoLines(64,
		"discovery/openredirect-params.txt",
		"openredirect-params.txt",
	)
	for _, raw := range extra {
		param := strings.ToLower(strings.TrimSpace(raw))
		if param == "" || seen[param] {
			continue
		}
		seen[param] = true
		params = append(params, param)
	}
	return params
}

func isTrustedRedirectTarget(rawLocation string) bool {
	location := strings.TrimSpace(rawLocation)
	if location == "" {
		return false
	}

	parsed, err := url.Parse(location)
	if err != nil {
		return false
	}

	host := strings.ToLower(parsed.Hostname())
	return host == "google.com" || strings.HasSuffix(host, ".google.com")
}

func ScanOpenRedirect(baseURL string, client *http.Client, onFound func(core.Finding)) {
	// 1. Identify parameters that might be vulnerable
	if !strings.Contains(baseURL, "=") {
		return
	}

	// Create a client that does NOT follow redirects
	noRedirectClient := &http.Client{
		Timeout: client.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, param := range mergedOpenRedirectParams() {
		if strings.Contains(strings.ToLower(baseURL), param+"=") {
			for _, payload := range OpenRedirectPayloads {
				// Inject payload into the parameter
				target := utils.InjectPayload(baseURL, param, payload)
				if target == "" {
					continue
				}

				req, err := http.NewRequest("GET", target, nil)
				if err != nil {
					continue
				}
				utils.SetDefaultHeaders(req, target)

				resp, err := noRedirectClient.Do(req)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				location := resp.Header.Get("Location")
				if isTrustedRedirectTarget(location) {
					onFound(core.Finding{
						Type:       "Open Redirect",
						Target:     target,
						Detail:     fmt.Sprintf("Parameter '%s' is vulnerable to Open Redirect. Redirects to: %s", param, location),
						Severity:   "Medium",
						Confidence: core.ConfidenceConfirmed,
					})
					return // Found one, move to next parameter or finish
				}
			}
		}
	}
}
