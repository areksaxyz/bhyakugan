package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yupiyy/bhyakugan/internal/core"
	"github.com/yupiyy/bhyakugan/internal/output"
	"github.com/yupiyy/bhyakugan/internal/payloadrepo"
	"github.com/yupiyy/bhyakugan/internal/recon"
	"github.com/yupiyy/bhyakugan/internal/scanner"
)

const version = "3.7"

func printBanner() {
	banner := `
   ▄▄▄▄    ██░ ██▓██   ██▓ ▄▄▄       ██ ▄█▀ █    ██   ▄████  ▄▄▄       ███▄    █
   ▓█████▄ ▓██░ ██▒▒██  ██▒▒████▄     ██▄█▒  ██  ▓██▒ ██▒ ▀█▒▒████▄     ██ ▀█   █
   ▒██▒ ▄██▒██▀▀██░ ▒██ ██░▒██  ▀█▄  ▓███▄░ ▓██  ▒██░▒██░▄▄▄░▒██  ▀█▄  ▓██  ▀█ ██▒
   ▒██░█▀  ░▓█ ░██  ░ ▐██▓░░██▄▄▄▄██ ▓██ █▄ ▓▓█  ░██░░▓█  ██▓░██▄▄▄▄██ ▓██▒  ▐▌██▒
   ░▓█  ▀█▓░▓█▒░██▓ ░ ██▒▓░ ▓█   ▓██▒▒██▒ █▄▒▒█████▓ ░▒▓███▀▒ ▓█   ▓██▒▒██░   ▓██░
   ░▒▓███▀▒ ▒ ░░▒░▒  ██▒▒▒  ▒▒   ▓▒█░▒ ▒▒ ▓▒░▒▓▒ ▒ ▒  ░▒   ▒  ▒▒   ▓▒█░░ ▒░   ▒ ▒
   ▒░▒   ░  ▒ ░▒░ ░▓██ ░▒░   ▒   ▒▒ ░░ ░▒ ▒░░░▒░ ░ ░   ░   ░   ▒   ▒▒ ░░ ░░   ░ ▒░
   ░    ░  ░  ░░ ░▒ ▒ ░░    ░   ▒   ░ ░░ ░  ░░░ ░ ░ ░ ░   ░   ░   ▒      ░   ░ ░
   ░       ░  ░  ░░ ░           ░  ░░  ░      ░           ░       ░  ░         ░
   ░         ░ ░

   [ BHYAKUGAN v%s - Automated Backend Security Scanner ]
   [ Created with ❤️ by areksaxyz (Arga Reksapati) ]
`
	fmt.Printf(banner, version)
}

func main() {
	domainPtr := flag.String("domain", "", "Domain utama untuk scan wildcard (Recon + Scan)")
	targetPtr := flag.String("target", "", "URL spesifik untuk dipindai (Single Mode)")
	depthPtr := flag.Int("depth", 1, "Kedalaman crawling (1 = page ini saja, 2+ = recursive)")
	payloadsPtr := flag.String("payloads", "", "Path ke file wordlist kustom (Opsional)")
	timeoutPtr := flag.Int("timeout", 10, "HTTP Timeout dalam detik")
	modePtr := flag.String("mode", "balanced", "Mode scan: strict, balanced, aggressive, bounty, lab")
	strictValidationPtr := flag.Bool("strict-validation", false, "Filter ketat: drop temuan heuristik-only")
	fastPtr := flag.Bool("fast", false, "Profil triage cepat (mengurangi modul berat)")
	maxEndpointsPtr := flag.Int("max-endpoints", 0, "Batas endpoint per host (0 = auto/unlimited)")
	pattPtr := flag.String("patt", "", "Path ke repo PayloadsAllTheThings (opsional)")

	flag.Parse()

	printBanner()

	if *domainPtr == "" && *targetPtr == "" {
		fmt.Println("[!] Error: Anda harus menentukan -domain atau -target.")
		flag.Usage()
		os.Exit(1)
	}

	// Auto-detect PayloadsAllTheThings if not provided
	if *pattPtr == "" {
		*pattPtr = detectPATT()
	}
	if *pattPtr != "" {
		fmt.Printf("[*] PayloadsAllTheThings path: %s\n", *pattPtr)
		os.Setenv("BHYAKUGAN_PATT", *pattPtr)
		payloadrepo.SetRoot(*pattPtr)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout: time.Duration(*timeoutPtr) * time.Second,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Follow redirects
		},
	}

	var allFindings []core.Finding
	var findingsMu sync.Mutex
	onFound := func(f core.Finding) {
		findingsMu.Lock()
		allFindings = append(allFindings, f)
		findingsMu.Unlock()

		color := "\033[34m" // Info
		switch f.Severity {
		case "Critical":
			color = "\033[31m"
		case "High":
			color = "\033[33m"
		case "Medium":
			color = "\033[35m"
		case "Low":
			color = "\033[32m"
		}
		fmt.Printf("[%s%s\033[0m] %s | %s | %s\n", color, f.Severity, f.Type, f.Target, f.Confidence)
	}

	var liveHosts []string
	var mainTarget string

	// Handle signals for graceful shutdown and report generation
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[!] Scan interrupted by user. Finalizing report...")
		findingsMu.Lock()
		if len(allFindings) > 0 {
			saveReport(allFindings, liveHosts, mainTarget)
		} else {
			fmt.Println("[*] No findings to report.")
		}
		findingsMu.Unlock()
		os.Exit(0)
	}()

	if *domainPtr != "" {
		mainTarget = *domainPtr
		subs, err := recon.RunSubdomainDiscovery(*domainPtr)
		if err != nil {
			fmt.Printf("[!] Error during recon: %v\n", err)
			os.Exit(1)
		}

		liveHosts, err = recon.FilterLiveHosts(subs)
		if err != nil {
			fmt.Printf("[!] Error filtering live hosts: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[*] Starting scans on %d live hosts...\n", len(liveHosts))
		sharedJS := &sync.Map{}
		for i, host := range liveHosts {
			fmt.Printf("\n[%d/%d] Scanning %s\n", i+1, len(liveHosts), host)
			opts := scanner.Options{
				Target:           host,
				Timeout:          *timeoutPtr,
				PayloadFile:      *payloadsPtr,
				Depth:            *depthPtr,
				SharedJS:         sharedJS,
				Mode:             *modePtr,
				StrictValidation: *strictValidationPtr,
				Fast:             *fastPtr,
				MaxEndpoints:     *maxEndpointsPtr,
			}
			scanner.Start(opts, client, onFound)
		}
	} else {
		mainTarget = *targetPtr
		liveHosts = []string{*targetPtr}
		opts := scanner.Options{
			Target:           *targetPtr,
			Timeout:          *timeoutPtr,
			PayloadFile:      *payloadsPtr,
			Depth:            *depthPtr,
			SharedJS:         &sync.Map{},
			Mode:             *modePtr,
			StrictValidation: *strictValidationPtr,
			Fast:             *fastPtr,
			MaxEndpoints:     *maxEndpointsPtr,
		}
		scanner.Start(opts, client, onFound)
	}

	// Generate Final Report
	findingsMu.Lock()
	saveReport(allFindings, liveHosts, mainTarget)
	findingsMu.Unlock()
}

func saveReport(allFindings []core.Finding, liveHosts []string, mainTarget string) {
	if len(allFindings) == 0 {
		return
	}
	outputDir := "bhyakugan-output"
	_ = os.MkdirAll(outputDir, 0755)

	safeTarget := strings.ReplaceAll(strings.ReplaceAll(mainTarget, "://", "_"), "/", "_")
	reportName := filepath.Join(outputDir, fmt.Sprintf("report_%s.html", safeTarget))

	fmt.Printf("\n[*] Generating HTML Report: %s\n", reportName)
	err := output.GenerateHTML(reportName, allFindings, liveHosts, mainTarget)
	if err != nil {
		fmt.Printf("[!] Error generating report: %v\n", err)
	} else {
		fmt.Printf("[+] Report saved successfully!\n")
	}
}

func detectPATT() string {
	// 1. Env
	if p := os.Getenv("BHYAKUGAN_PATT"); p != "" {
		return p
	}
	// 2. Local search
	paths := []string{
		"./PayloadsAllTheThings",
		"../PayloadsAllTheThings",
		"../../PayloadsAllTheThings",
		filepath.Join(os.Getenv("HOME"), "tools", "PayloadsAllTheThings"),
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
