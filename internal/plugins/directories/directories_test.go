package directories

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/areksaxyz/bhyakugan/internal/payloadrepo"
)

func TestHasStrongSecretEvidence(t *testing.T) {
	if hasStrongSecretEvidence("<html>hello world</html>") {
		t.Fatal("expected false for generic HTML")
	}
	if !hasStrongSecretEvidence("aws_access_key_id=AKIA1234567890ABCDEF") {
		t.Fatal("expected true for AWS credential indicator")
	}
}

func TestIsLikelySQLDump(t *testing.T) {
	if !isLikelySQLDump("-- MySQL dump\nCREATE TABLE users(id int);") {
		t.Fatal("expected SQL dump detection")
	}
	if isLikelySQLDump("<html>not an sql dump</html>") {
		t.Fatal("expected non-sql html to be false")
	}
}

func TestIsAutodiscoverConfigRedirect(t *testing.T) {
	base := "http://autodiscover.tiktok.com/"
	final := "https://outlook.office365.com/config.php?realm=tiktok.com&vd=autodiscover"
	if !isAutodiscoverConfigRedirect(base, "config.php", final) {
		t.Fatal("expected autodiscover redirect to be ignored")
	}

	if isAutodiscoverConfigRedirect("https://example.com/", "config.php", "https://example.com/config.php") {
		t.Fatal("expected same-host config.php to not be ignored")
	}
}

func TestIsLikelyPHPConfigSource(t *testing.T) {
	raw := `<?php
define('DB_HOST', 'localhost');
$db_password = 'secret';
`
	if !isLikelyPHPConfigSource(raw, "text/plain", false) {
		t.Fatal("expected raw php config source to be detected")
	}

	html := `<html><body>config.php</body></html>`
	if isLikelyPHPConfigSource(html, "text/html", true) {
		t.Fatal("expected html fallback page to be rejected")
	}
}

func TestDiscoveryChecksIncludeInterestingFileWordlist(t *testing.T) {
	restoreWordlistsRoot(t)

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("test"), 0644); err != nil {
		t.Fatalf("write README failed: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "verify"), 0755); err != nil {
		t.Fatalf("mkdir verify failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "verify", "file-interesting-names.txt"), []byte("tenant-backup.zip\n"), 0644); err != nil {
		t.Fatalf("write wordlist failed: %v", err)
	}
	payloadrepo.SetWordlistsRoot(root)

	checks := discoveryChecks()
	for _, check := range checks {
		if check.Path == "tenant-backup.zip" {
			return
		}
	}
	t.Fatal("expected discovery checks to include verify/file-interesting-names.txt entries")
}

func restoreWordlistsRoot(t *testing.T) {
	t.Helper()
	original := payloadrepo.WordlistsRoot()
	t.Cleanup(func() {
		if original != "" {
			payloadrepo.SetWordlistsRoot(original)
		}
	})
}
