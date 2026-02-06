package recon

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// RunSubdomainDiscovery runs subfinder and assetfinder
func RunSubdomainDiscovery(domain string) ([]string, error) {
	fmt.Printf("[*] Running Subdomain Discovery on %s...\n", domain)
	
	uniqueSubs := make(map[string]bool)

	// 1. Run Subfinder
	fmt.Println("    -> Running subfinder...")
	cmd := exec.Command("subfinder", "-d", domain, "-silent")
	output, err := cmd.CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
			
uniqueSubs[line] = true
			}
		}
	} else {
		fmt.Printf("    [!] Error running subfinder: %v\n", err)
	}

	// 2. Run Assetfinder
	fmt.Println("    -> Running assetfinder...")
	cmd2 := exec.Command("assetfinder", "--subs-only", domain)
	output2, err := cmd2.CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output2), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
			
uniqueSubs[line] = true
			}
		}
	} else {
		fmt.Printf("    [!] Error running assetfinder: %v\n", err)
	}

	var results []string
	for sub := range uniqueSubs {
		results = append(results, sub)
	}
	fmt.Printf("    -> Found %d unique subdomains.\n", len(results))
	return results, nil
}

// FilterLiveHosts runs httpx on the list of subdomains
func FilterLiveHosts(subdomains []string) ([]string, error) {
	fmt.Println("[*] Filtering Live Hosts with httpx...")
	
	cmd := exec.Command("httpx", "-silent", "-no-color")
	
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
