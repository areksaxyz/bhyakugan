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
