package payloadrepo

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	rootPath = "/home/yupiyy/tools/bug/PayloadsAllTheThings"
	mu       sync.RWMutex
	cache    = make(map[string][]string)
)

func SetRoot(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if path != rootPath {
		rootPath = path
		cache = make(map[string][]string)
	}
}

func Root() string {
	mu.RLock()
	defer mu.RUnlock()
	return rootPath
}

func LoadLines(relPath string, max int) []string {
	if max <= 0 {
		max = 100
	}

	mu.RLock()
	key := rootPath + "|" + relPath
	if v, ok := cache[key]; ok {
		out := clone(v)
		mu.RUnlock()
		return out
	}
	mu.RUnlock()

	abs := filepath.Join(Root(), relPath)
	f, err := os.Open(abs)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "```") {
			continue
		}
		if strings.HasPrefix(line, "![") || strings.HasPrefix(line, "[!") {
			continue
		}
		if len(line) > 220 {
			continue
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
		if len(out) >= max {
			break
		}
	}

	mu.Lock()
	cache[key] = clone(out)
	mu.Unlock()
	return out
}

func clone(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
