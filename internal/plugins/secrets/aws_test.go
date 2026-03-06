package secrets

import (
	"strings"
	"testing"
	"github.com/yupiyy/bhyakugan/internal/core"
)

func TestDetectInContent_AWSPair(t *testing.T) {
	content := `
		AWS_ACCESS_KEY_ID=AKIAABCDEF0123456789
		AWS_SECRET_ACCESS_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
	`
	var findings []core.Finding
	DetectInContent(content, "https://example.com/config", func(f core.Finding) {
		findings = append(findings, f)
	})

	foundPair := false
	for _, f := range findings {
		expectedDetail := "Found AWS Pair (Access Key ID and Secret Access Key) in the same content. This is a High Signal for Valid Credentials.\nAccess Key: AKIAABCDEF0123456789\nSecret Key: [REDACTED]"
		if f.Severity == "High" && f.Detail == expectedDetail {
			foundPair = true
		}
	}

	if !foundPair {
		t.Errorf("Expected AWS Pair finding, but it was not found. Findings: %+v", findings)
	}
}

func TestDetectInContent_AWSLowEntropySecret(t *testing.T) {
	// A repetitive string has low entropy
	content := `AWS_SECRET_ACCESS_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`
	var findings []core.Finding
	DetectInContent(content, "https://example.com/config", func(f core.Finding) {
		findings = append(findings, f)
	})

	for _, f := range findings {
		if strings.Contains(f.Detail, "AWS Secret Access Key") {
			t.Errorf("Expected no AWS Secret Access Key finding due to low entropy, but got: %+v", f)
		}
	}
}

func TestDetectInContent_AWSSingleSecret(t *testing.T) {
	// A random-looking string has high entropy
	content := `AWS_SECRET_ACCESS_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0`
	var findings []core.Finding
	DetectInContent(content, "https://example.com/config", func(f core.Finding) {
		findings = append(findings, f)
	})

	foundSecret := false
	for _, f := range findings {
		// Individual AWS Secret Key with no Access Key found in same content should be "Low" severity now
		if f.Severity == "Low" && strings.Contains(f.Detail, "AWS Secret Access Key") {
			foundSecret = true
		}
	}

	if !foundSecret {
		t.Errorf("Expected individual AWS Secret Access Key finding with context, but it was not found. Findings: %+v", findings)
	}
}

func TestDetectInContent_AWSSecretNoContext(t *testing.T) {
	// A random 40-char string without 'aws' or 'key' keywords nearby
	content := `Some random data that happens to have a 40 char string a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0 in the middle of it.`
	var findings []core.Finding
	DetectInContent(content, "https://example.com/page", func(f core.Finding) {
		findings = append(findings, f)
	})

	for _, f := range findings {
		if strings.Contains(f.Detail, "AWS Secret Access Key") {
			t.Errorf("Expected NO AWS Secret Access Key finding due to lack of context, but got: %+v", f)
		}
	}
}
