package crawler

import (
	"net/url"
	"regexp"
	"strings"
)

// ExtractLinks finds all internal links in the HTML body
func ExtractLinks(baseURL string, htmlBody string) []string {
	var links []string
	seen := make(map[string]bool)

	// Parse Base URL
	u, err := url.Parse(baseURL)
	if err != nil {
		return links
	}
	baseHost := u.Host

	// Regex to find hrefs, srcs, and actions (More rigorous extraction)
	re := regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']?([^"' >]+)["']?`)
	matches := re.FindAllStringSubmatch(htmlBody, -1)

	for _, match := range matches {
		if len(match) > 1 {
			rawLink := strings.TrimSpace(match[1])

			// Filter out junk
			if rawLink == "" || strings.HasPrefix(rawLink, "#") || strings.HasPrefix(rawLink, "javascript:") || strings.HasPrefix(rawLink, "mailto:") {
				continue
			}

			// Resolve relative URLs (Professional approach)
			parsedRaw, errRaw := url.Parse(rawLink)
			if errRaw != nil {
				continue
			}
			resolvedURL := u.ResolveReference(parsedRaw).String()

			// Verify Domain Scope (Internal Only)
			parsedResolved, err := url.Parse(resolvedURL)
			if err == nil {
				if parsedResolved.Host == baseHost {
					// Exclude Static Files (Images, CSS, Fonts) to save time
					if !isStaticFile(parsedResolved.Path) {
						if !seen[resolvedURL] {
							seen[resolvedURL] = true
							links = append(links, resolvedURL)
						}
					}
				}
			}
		}
	}
	return links
}

func isStaticFile(path string) bool {
	exts := []string{".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".pdf"}
	lowerPath := strings.ToLower(path)
	for _, ext := range exts {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	return false
}
