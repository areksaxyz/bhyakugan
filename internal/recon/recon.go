package recon

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

func checkToolAvailability(tool string) bool {
	if _, err := exec.LookPath(tool); err != nil {
		fmt.Printf("    [!] Missing dependency: %s not found in PATH\n", tool)
		return false
	}
	return true
}

// RunSubdomainDiscovery runs subfinder and assetfinder in parallel and merges with existing results
func RunSubdomainDiscovery(domain string) ([]string, error) {
	fmt.Printf("[*] Running Subdomain Discovery on %s...\n", domain)
	subfinderAvailable := checkToolAvailability("subfinder")
	assetfinderAvailable := checkToolAvailability("assetfinder")
	curlAvailable := checkToolAvailability("curl")

	outputDir := "bhyakugan-output"
	historyFile := filepath.Join(outputDir, fmt.Sprintf("subdomains_%s.txt", strings.ReplaceAll(domain, ".", "_")))

	uniqueSubs := make(map[string]bool)
	var mu sync.Mutex

	// Load existing history if available
	if _, err := os.Stat(historyFile); err == nil {
		content, _ := os.ReadFile(historyFile)
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				uniqueSubs[line] = true
			}
		}
		if len(uniqueSubs) > 0 {
			fmt.Printf("    -> Loaded %d existing subdomains from history.\n", len(uniqueSubs))
		}
	}

	var wg sync.WaitGroup

	// 1. Run Subfinder
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !subfinderAvailable {
			fmt.Println("    [!] Skipping subfinder discovery because the binary is unavailable.")
			return
		}
		fmt.Println("    -> Running subfinder...")
		// Use -all to ensure all sources are used, even slow ones.
		cmd := exec.Command("subfinder", "-d", domain, "-all", "-silent")
		output, err := cmd.CombinedOutput()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			mu.Lock()
			count := 0
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					uniqueSubs[line] = true
					count++
				}
			}
			fmt.Printf("    [+] Subfinder found %d subdomains.\n", count)
			mu.Unlock()
		} else {
			fmt.Printf("    [!] Error running subfinder: %v\n", err)
		}
	}()

	// 2. Run Assetfinder
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !assetfinderAvailable {
			fmt.Println("    [!] Skipping assetfinder discovery because the binary is unavailable.")
			return
		}
		fmt.Println("    -> Running assetfinder...")
		cmd2 := exec.Command("assetfinder", "--subs-only", domain)
		output2, err := cmd2.CombinedOutput()
		if err == nil {
			lines := strings.Split(string(output2), "\n")
			mu.Lock()
			count := 0
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					uniqueSubs[line] = true
					count++
				}
			}
			fmt.Printf("    [+] Assetfinder found %d subdomains.\n", count)
			mu.Unlock()
		} else {
			fmt.Printf("    [!] Error running assetfinder: %v\n", err)
		}
	}()

	// 3. Run crt.sh query (Direct API)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !curlAvailable {
			fmt.Println("    [!] Skipping crt.sh query because curl is unavailable.")
			return
		}
		fmt.Println("    -> Querying crt.sh...")
		// Simple crt.sh query using curl/grep to avoid heavy dependencies
		// Output format: JSON or plain text. We'll use a simple approach.
		query := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
		cmd3 := exec.Command("curl", "-s", query)
		output3, err := cmd3.CombinedOutput()
		if err == nil {
			// Extract common_name and name_value using simple string matching or regex
			// to avoid importing a JSON parser if not needed, but strings.Contains is enough for basic extraction
			lines := strings.Split(string(output3), ",")
			mu.Lock()
			count := 0
			for _, line := range lines {
				if strings.Contains(line, "name_value") {
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						sub := strings.Trim(parts[1], "\"")
						// Handle multiple subdomains in one field (newline separated in crt.sh)
						subs := strings.Split(sub, "\\n")
						for _, s := range subs {
							s = strings.TrimSpace(s)
							if strings.HasSuffix(s, domain) && !strings.Contains(s, "*") {
								uniqueSubs[s] = true
								count++
							}
						}
					}
				}
			}
			fmt.Printf("    [+] crt.sh API found %d potential subdomains.\n", count)
			mu.Unlock()
		} else {
			fmt.Printf("    [!] Error querying crt.sh: %v\n", err)
		}
	}()

	wg.Wait()

	var results []string
	for sub := range uniqueSubs {
		results = append(results, sub)
	}

	// Save merged results to history file
	_ = os.MkdirAll(outputDir, 0755)
	historyData := strings.Join(results, "\n")
	_ = os.WriteFile(historyFile, []byte(historyData), 0644)

	fmt.Printf("    -> Found %d unique subdomains (merged with history).\n", len(results))
	return results, nil
}

// FilterLiveHosts runs httpx on the list of subdomains
func FilterLiveHosts(subdomains []string, threads int) ([]string, error) {
	fmt.Println("[*] Filtering Live Hosts with httpx...")
	if !checkToolAvailability("httpx") {
		return nil, fmt.Errorf("httpx not found in PATH")
	}

	concurrency := "50"
	if threads > 0 {
		concurrency = fmt.Sprintf("%d", threads)
	}

	// Add timeout to prevent hanging
	cmd := exec.Command("httpx", "-silent", "-no-color", "-t", concurrency, "-rl", "150", "-timeout", "5")

	// Pass subdomains via Stdin
	var stdin bytes.Buffer
	for _, sub := range subdomains {
		stdin.WriteString(sub + "\n")
	}
	cmd.Stdin = &stdin

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	var liveHosts []string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		host := strings.TrimSpace(scanner.Text())
		if host != "" {
			liveHosts = append(liveHosts, host)
		}
	}

	fmt.Printf("    -> Found %d live hosts.\n", len(liveHosts))
	return liveHosts, nil
}
