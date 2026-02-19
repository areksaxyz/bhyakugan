package directories

import "testing"

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
