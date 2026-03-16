package recon_html

import (
	"fmt"
	"regexp"

	"github.com/yupiyy/bhyakugan/internal/core"
)

var (
	// CSRF Tokens in HTML Forms
	csrfRegex = regexp.MustCompile(`(?i)<input\s+[^>]*type=["']hidden["'][^>]*name=["']([^"']*(?:csrf|token|xsrf|authenticity)[^"']*)["'][^>]*value=["']([^"']{8,})["']`)

	// Session IDs in HTML (more flexible for key=value or key: "value")
	sessionRegex = regexp.MustCompile(`(?i)(?:sessionid|phpsessid|jsessionid|aspsessionid|connect\.sid|sid)\s*[:=]\s*["']?([^"'\s]{8,})["']?`)

	// Login Forms (using ?s for dot-matches-all)
	loginFormRegex = regexp.MustCompile(`(?is)<form[^>]*>.*<input[^>]*type=["']password["'][^>]*>.*</form>`)

	// ReCaptcha
	recaptchaRegex = regexp.MustCompile(`(?i)(?:g-recaptcha|google\.com/recaptcha|recaptcha\.net)`)

	// OAuth/Client IDs
	clientIDRegex     = regexp.MustCompile(`(?i)(?:client_id|clientid|app_id|appid)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{12,})["']?`)
	clientSecretRegex = regexp.MustCompile(`(?i)(?:client_secret|clientsecret|app_secret|appsecret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{24,})["']?`)
)

func Scan(url string, body string, onFound func(core.Finding)) {
	// 1. Detect CSRF Tokens
	detectCSRF(url, body, onFound)

	// 2. Detect Session IDs
	detectSessionID(url, body, onFound)

	// 3. Detect Login Forms
	detectLoginForm(url, body, onFound)

	// 4. Detect ReCaptcha
	detectReCaptcha(url, body, onFound)

	// 5. Detect Client IDs/Secrets
	detectOAuth(url, body, onFound)
}

func detectCSRF(url string, body string, onFound func(core.Finding)) {
	matches := csrfRegex.FindAllStringSubmatch(body, -1)
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 2 {
			name := m[1]
			value := m[2]
			if !seen[value] {
				onFound(core.Finding{
					Type:     "Recon: CSRF Token Found",
					Target:   url,
					Detail:   fmt.Sprintf("Found hidden CSRF token in form: name=%s, value=%s", name, value),
					Severity: "Info",
				})
				seen[value] = true
			}
		}
	}
}

func detectSessionID(url string, body string, onFound func(core.Finding)) {
	matches := sessionRegex.FindAllStringSubmatch(body, -1)
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 {
			value := m[1]
			if !seen[value] {
				onFound(core.Finding{
					Type:     "Recon: Session ID Found",
					Target:   url,
					Detail:   fmt.Sprintf("Potential Session ID leaked in HTML: %s", value),
					Severity: "Low",
				})
				seen[value] = true
			}
		}
	}
}

func detectLoginForm(url string, body string, onFound func(core.Finding)) {
	if loginFormRegex.MatchString(body) {
		onFound(core.Finding{
			Type:     "Recon: Login Form Detected",
			Target:   url,
			Detail:   "Login form with password input discovered.",
			Severity: "Info",
		})
	}
}

func detectReCaptcha(url string, body string, onFound func(core.Finding)) {
	if recaptchaRegex.MatchString(body) {
		onFound(core.Finding{
			Type:     "Recon: ReCaptcha Detected",
			Target:   url,
			Detail:   "Google ReCaptcha or similar bot protection detected on this page.",
			Severity: "Info",
		})
	}
}

func detectOAuth(url string, body string, onFound func(core.Finding)) {
	// Client ID
	idMatches := clientIDRegex.FindAllStringSubmatch(body, -1)
	seenID := make(map[string]bool)
	for _, m := range idMatches {
		if len(m) > 1 {
			val := m[1]
			if !seenID[val] {
				onFound(core.Finding{
					Type:     "Recon: Client ID Found",
					Target:   url,
					Detail:   fmt.Sprintf("Found OAuth/App Client ID: %s", val),
					Severity: "Info",
				})
				seenID[val] = true
			}
		}
	}

	// Client Secret
	secretMatches := clientSecretRegex.FindAllStringSubmatch(body, -1)
	seenSecret := make(map[string]bool)
	for _, m := range secretMatches {
		if len(m) > 1 {
			val := m[1]
			if !seenSecret[val] {
				onFound(core.Finding{
					Type:     "Recon: Client Secret Found",
					Target:   url,
					Detail:   fmt.Sprintf("Found OAuth/App Client Secret: %s", val),
					Severity: "Medium",
				})
				seenSecret[val] = true
			}
		}
	}
}
