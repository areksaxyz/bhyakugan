package payloadrepo

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	localMu         sync.RWMutex
	localRootPath   string
	localCache      = make(map[string][]string)
	currentScanMode = "balanced"
)

func SetScanMode(mode string) {
	localMu.Lock()
	currentScanMode = normalizeScanMode(mode)
	localMu.Unlock()
}

func ScanMode() string {
	localMu.RLock()
	defer localMu.RUnlock()
	return currentScanMode
}

func SetWordlistsRoot(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return
	}

	localMu.Lock()
	defer localMu.Unlock()
	if abs != localRootPath {
		localRootPath = abs
		localCache = make(map[string][]string)
	}
}

func WordlistsRoot() string {
	localMu.RLock()
	root := localRootPath
	localMu.RUnlock()
	if root != "" {
		return root
	}
	return AutoDetectWordlists()
}

func AutoDetectWordlists() string {
	candidates := []string{}
	if env := strings.TrimSpace(os.Getenv("BHYAKUGAN_WORDLISTS")); env != "" {
		candidates = append(candidates, env)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wordlistCandidates(wd)...)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, wordlistCandidates(filepath.Dir(exe))...)
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		candidates = append(candidates, wordlistCandidates(filepath.Dir(file))...)
	}

	seen := make(map[string]bool)
	for _, candidate := range candidates {
		abs, err := filepath.Abs(strings.TrimSpace(candidate))
		if err != nil || seen[abs] {
			continue
		}
		seen[abs] = true

		info, err := os.Stat(abs)
		if err != nil || !info.IsDir() {
			continue
		}
		if looksLikeWordlistRoot(abs) {
			SetWordlistsRoot(abs)
			return abs
		}
	}
	return ""
}

func LoadRepoLines(max int, relPaths ...string) []string {
	if max <= 0 {
		max = 100
	}
	root := WordlistsRoot()
	if root == "" {
		return nil
	}

	seen := make(map[string]bool)
	out := make([]string, 0, max)
	for _, relPath := range relPaths {
		relPath = strings.TrimSpace(relPath)
		if relPath == "" {
			continue
		}

		key := root + "|" + relPath
		localMu.RLock()
		cached, ok := localCache[key]
		localMu.RUnlock()
		lines := clone(cached)
		if !ok {
			lines = loadUniqueLinesFromFile(filepath.Join(root, relPath), max)
			localMu.Lock()
			localCache[key] = clone(lines)
			localMu.Unlock()
		}

		for _, line := range lines {
			if seen[line] {
				continue
			}
			seen[line] = true
			out = append(out, line)
			if len(out) >= max {
				return out
			}
		}
	}

	return out
}

func looksLikeWordlistRoot(root string) bool {
	probes := []string{
		filepath.Join(root, "README.md"),
		filepath.Join(root, "paths-common.txt"),
		filepath.Join(root, "discovery"),
	}
	for _, probe := range probes {
		if _, err := os.Stat(probe); err == nil {
			return true
		}
	}
	return false
}

func wordlistCandidates(start string) []string {
	dir := filepath.Clean(start)
	out := make([]string, 0, 7)
	for i := 0; i < 7; i++ {
		out = append(out, filepath.Join(dir, "wordlists"))
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return out
}

func normalizeScanMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "balanced":
		return "balanced"
	case "bounty", "strict":
		return "strict"
	case "lab", "aggressive":
		return "aggressive"
	default:
		return "balanced"
	}
}
