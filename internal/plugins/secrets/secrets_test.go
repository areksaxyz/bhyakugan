package secrets

import (
	"testing"

	"github.com/areksaxyz/bhyakugan/internal/core"
)

func TestDetectInContent_DocsBackupReferenceIsIgnored(t *testing.T) {
	content := `How to backup DB: mysqldump -u user -p db > backup.sql`
	var findings []core.Finding

	DetectInContent(content, "https://example.com/docs", func(f core.Finding) {
		findings = append(findings, f)
	})

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for docs reference, got %d: %+v", len(findings), findings)
	}
}

func TestIsLikelyRealPrivateKeyBlock(t *testing.T) {
	fake := `-----BEGIN PRIVATE KEY-----","").replace("-----END PRIVATE KEY-----`
	if isLikelyRealPrivateKeyBlock(fake) {
		t.Fatal("expected fake/private-key string replacement snippet to be ignored")
	}

	realLike := "-----BEGIN PRIVATE KEY-----\n" +
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD6wS4yH7o6Kq5l\n" +
		"Vubq4J3w+h7bYwU4H9K8o4WbE0fT3fK6YvFqK4hQk1L8i5P7H4q6kM3r9L8mA2p0\n" +
		"YxD7k8nP2Qf9x7pWf8vH2fJrM0q9Qk3nN1o8R7tP0k1mD2f8A9bC3dE4fG5hI6jK\n" +
		"xk9fQ2l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8AaBbCcDdEeFfGgHhIiJjKkLlMmNn\n" +
		"OoPpQqRrSsTtUuVvWwXxYyZz0123456789abcdefABCDEFghijklmnopqrstuv==\n" +
		"-----END PRIVATE KEY-----"
	if !isLikelyRealPrivateKeyBlock(realLike) {
		t.Fatal("expected real-like private key block to be accepted")
	}
}
