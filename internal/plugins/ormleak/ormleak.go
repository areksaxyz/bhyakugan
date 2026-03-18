package ormleak

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/areksaxyz/bhyakugan/internal/core"
)

type ORMPayload struct {
	Name    string
	Payload string
}

var ORMPayloads = []ORMPayload{
	{"Django ORM Leak (__startswith)", "?user__startswith=adm"},
	{"Django ORM Leak (__contains)", "?user__contains=dmi"},
	{"Django ORM Leak (__regex)", "?user__regex=^adm"},
	{"Ransack ORM Leak (_start)", "?q[username_start]=adm"},
	{"Ransack ORM Leak (_cont)", "?q[username_cont]=dmi"},
}

// Scan tests for ORM Information Leakage
func Scan(baseURL string, client *http.Client, onFound func(core.Finding)) {
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	// 0. Establish Baseline & Tech Detection
	respBase, errBase := client.Get(baseURL)
	isRails := false
	isDjango := false

	if errBase == nil {
		// Tech Stack Detection
		headers := respBase.Header
		server := strings.ToLower(headers.Get("Server"))
		poweredBy := strings.ToLower(headers.Get("X-Powered-By"))
		cookies := strings.Join(headers.Values("Set-Cookie"), " ")
		baseBody, _ := io.ReadAll(io.LimitReader(io.LimitReader(respBase.Body, 5*1024*1024), 5*1024*1024))
		baseBodyStr := strings.ToLower(string(baseBody))
		respBase.Body.Close()

		// Rails Fingerprints
		if headers.Get("X-GitHub-Request-Id") != "" ||
			strings.Contains(server, "github") ||
			headers.Get("X-Runtime") != "" ||
			headers.Get("X-Rack-Cache") != "" ||
			strings.Contains(cookies, "_session_id") ||
			strings.Contains(baseBodyStr, "rails") || strings.Contains(baseBodyStr, "turbolinks") {
			isRails = true
		}

		// Django Fingerprints
		if strings.Contains(cookies, "csrftoken") ||
			strings.Contains(cookies, "sessionid") ||
			strings.Contains(poweredBy, "django") ||
			strings.Contains(server, "gunicorn") ||
			strings.Contains(baseBodyStr, "csrfmiddlewaretoken") || strings.Contains(baseBodyStr, "django") {
			isDjango = true
		}
	} else {
		return // Can't establish baseline
	}

	// Optimization: Only scan if one of the supported frameworks is detected
	if !isRails && !isDjango {
		return
	}

	for _, p := range ORMPayloads {
		// Smart Skip: Don't test Django payloads on Rails targets and vice versa (optimization)
		if isRails && strings.Contains(p.Name, "Django") {
			continue
		}
		if isDjango && strings.Contains(p.Name, "Ransack") {
			continue
		}

		target := baseURL + p.Payload
		resp, err := client.Get(target)
		if err != nil {
			continue
		}

		bodyBytes, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
		bodyStr := string(bodyBytes)
		resp.Body.Close()

		// --- ANTI-FALSE POSITIVE: Control Check ---
		// Fetch with a value that should NOT exist
		controlURL := baseURL + strings.Replace(p.Payload, "adm", "bhyakugan_non_existent_xyz", 1)
		respC, errC := client.Get(controlURL)
		if errC == nil {
			bodyC, _ := io.ReadAll(io.LimitReader(io.LimitReader(respC.Body, 5*1024*1024), 5*1024*1024))

			// 1. Length Comparison
			if len(bodyBytes) == len(bodyC) {
				respC.Body.Close()
				continue // Identical response = False Positive
			}

			// 2. Content Key Comparison (If "admin" is in BOTH, it's just static text)
			bodyCLower := strings.ToLower(string(bodyC))
			if strings.Contains(bodyCLower, "admin") || strings.Contains(bodyCLower, "success") {
				respC.Body.Close()
				continue // Keyword exists in control page -> Static content
			}

			respC.Body.Close()
		}

		// FP Check: Soft 404
		bodyLower := strings.ToLower(bodyStr)
		if strings.Contains(bodyLower, "<title>page not found") || strings.Contains(bodyLower, "<title>error") {
			continue
		}

		if resp.StatusCode == 200 && (strings.Contains(bodyLower, "admin") || strings.Contains(bodyLower, "success")) {
			// Severity Gating (Priority 2)
			severity := "Info" // Default to Info (Suspicious Parameter)
			detail := fmt.Sprintf("Server responded differently to ORM payload '%s'.", p.Name)

			// Upgrade if Framework matches
			if strings.Contains(p.Name, "Django") {
				if isDjango {
					severity = "Medium"
					detail = fmt.Sprintf("Django ORM Leak detected (Framework Verified: Django). %s", detail)
				} else {
					detail += " (Note: Django framework NOT confirmed, lower confidence)"
				}
			} else if strings.Contains(p.Name, "Ransack") {
				if isRails {
					severity = "Medium"
					detail = fmt.Sprintf("Ransack ORM Leak detected (Framework Verified: Rails). %s", detail)
				} else {
					detail += " (Note: Rails framework NOT confirmed, lower confidence)"
				}
			}

			// Upgrade if Explicit Leak Structure Found
			if strings.Contains(bodyStr, "HASH(") || strings.Contains(bodyStr, "Array") || strings.Contains(bodyStr, "System.Collections") {
				severity = "High"
				detail += " Evidence: Internal data structure leaked."
			}

			fmt.Printf("[!] MATCH: %s at %s [%s]\n", p.Name, target, severity)
			onFound(core.Finding{
				Type:     "ORM Leak",
				Target:   target,
				Detail:   detail,
				Severity: severity,
			})
		}
	}
}
