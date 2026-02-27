package pp

import (
	"net/http"
	"strings"
	"testing"
)

func TestJSONSpacesPayloadIsOnlyLowSignal(t *testing.T) {
	payload := Payloads[0]
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	isVuln, sev, ev := payload.Check(resp, "{\n          \"ok\": true\n}", 200, "{\"ok\":true}")
	if !isVuln {
		t.Fatal("expected formatting differential to be reported as signal")
	}
	if sev != "Low" {
		t.Fatalf("expected Low severity for formatting-only signal, got %q", sev)
	}
	if !strings.Contains(strings.ToLower(ev), "potential") {
		t.Fatalf("expected potential-signal wording, got %q", ev)
	}
}

func TestJSONSpacesPayloadIgnoredWhenControlAlsoFormatted(t *testing.T) {
	payload := Payloads[0]
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	isVuln, _, _ := payload.Check(resp, "{\n          \"ok\": true\n}", 200, "{\n          \"ok\": false\n}")
	if isVuln {
		t.Fatal("expected no finding when control has same formatting behavior")
	}
}

func TestStatusCodePayloadNeedsControlDifferential(t *testing.T) {
	payload := Payloads[2]
	resp := &http.Response{
		StatusCode: 510,
		Header:     make(http.Header),
	}

	isVuln, sev, _ := payload.Check(resp, "{}", 200, "{}")
	if !isVuln {
		t.Fatal("expected vulnerability when status changed only on polluted request")
	}
	if sev != "High" {
		t.Fatalf("expected High severity for status-code differential, got %q", sev)
	}

	isVulnSame, _, _ := payload.Check(resp, "{}", 510, "{}")
	if isVulnSame {
		t.Fatal("expected no finding when control has same 510 status")
	}
}
