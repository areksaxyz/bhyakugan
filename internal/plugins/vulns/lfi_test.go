package vulns

import "testing"

func TestIsTraversalPayload(t *testing.T) {
	cases := []string{
		"../../etc/passwd",
		"%2e%2e/%2e%2e/.env",
		"%252e%252e%252fetc%252fpasswd",
		"%u002e%u002e/%u002e%u002e/etc/passwd",
		"index.php/%2e%2e/%2e%2e/.env",
	}
	for _, c := range cases {
		if !isTraversalPayload(c) {
			t.Fatalf("expected traversal payload: %s", c)
		}
	}

	if isTraversalPayload("profile?id=1") {
		t.Fatal("expected non-traversal payload to be false")
	}
}

func TestLooksLikeEnvLeak(t *testing.T) {
	valid := "APP_KEY=base64:abc123\nAPP_ENV=production\nDB_HOST=127.0.0.1\nDB_PASSWORD=secret"
	if !looksLikeEnvLeak(valid) {
		t.Fatal("expected valid env leak markers to return true")
	}

	invalid := "this page explains APP_KEY= syntax only"
	if looksLikeEnvLeak(invalid) {
		t.Fatal("expected non-env content to be rejected")
	}
}
