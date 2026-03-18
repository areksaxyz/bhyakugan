package ssrf

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/areksaxyz/bhyakugan/internal/core"
)

func TestMatchesSSRFFingerprintOracleNeedsMultipleKeys(t *testing.T) {
	weak := "instance"
	if matchesSSRFFingerprint("oracle_meta", weak) {
		t.Fatal("expected weak single-word oracle signal to be rejected")
	}

	strong := "instance-id ocid1.instance.oc1..x availability-domain PHX-AD-1 compartment-id ocid1.compartment.oc1..abc"
	if !matchesSSRFFingerprint("oracle_meta", strong) {
		t.Fatal("expected oracle metadata key set to be accepted")
	}
}

func TestMatchesSSRFFingerprintPasswdRequiresStructure(t *testing.T) {
	if matchesSSRFFingerprint("passwd_file", "root:x: maybe fake") {
		t.Fatal("expected weak passwd substring to be rejected")
	}
	if !matchesSSRFFingerprint("passwd_file", "root:x:0:0:root:/root:/bin/bash") {
		t.Fatal("expected passwd structure to be accepted")
	}
}

func TestClassifySSRFFindingMetadataIsInformational(t *testing.T) {
	sev, conf, detail := classifySSRFFinding(SSRFPayload{
		Name:     "SSRF Cloud (AWS/GCP)",
		Detector: "aws_meta",
	})
	if sev != "Medium" {
		t.Fatalf("expected Medium severity for metadata-only SSRF signal without OOB, got %q", sev)
	}
	if conf != "probable" {
		t.Fatalf("expected probable confidence for metadata-only SSRF signal, got %q", conf)
	}
	if detail == "" {
		t.Fatal("expected non-empty detail")
	}
}

func TestClassifySSRFFindingPasswdRemainsConfirmed(t *testing.T) {
	sev, conf, _ := classifySSRFFinding(SSRFPayload{
		Name:     "SSRF File Scheme",
		Detector: "passwd_file",
	})
	if sev != "High" {
		t.Fatalf("expected High severity for deterministic file SSRF signal, got %q", sev)
	}
	if conf != "confirmed" {
		t.Fatalf("expected confirmed confidence for deterministic file SSRF signal, got %q", conf)
	}
}

func TestIsSSRFSinkParam(t *testing.T) {
	if !isSSRFSinkParam("url") {
		t.Fatal("expected url to be accepted as SSRF sink parameter")
	}
	if !isSSRFSinkParam("redirect_to") {
		t.Fatal("expected redirect_to to be accepted as SSRF-like parameter")
	}
	if isSSRFSinkParam("ver") {
		t.Fatal("expected ver cache-buster parameter to be rejected for SSRF fuzzing")
	}
}

func TestIsStaticAssetURL(t *testing.T) {
	if !isStaticAssetURL("https://example.com/wp-includes/js/dist/script-modules/interactivity/index.min.js?ver=6.7.1") {
		t.Fatal("expected static JS URL to be recognized as asset and skipped")
	}
	if isStaticAssetURL("https://example.com/api/fetch?url=http://169.254.169.254/latest/meta-data/") {
		t.Fatal("expected API endpoint URL to not be treated as static asset")
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestScanSkipsStaticAssetTarget(t *testing.T) {
	var hits int32
	client := &http.Client{
		Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
			atomic.AddInt32(&hits, 1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ok")),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}

	Scan("https://example.com/wp-includes/js/dist/script-modules/interactivity/index.min.js?ver=6.7.1", client, func(_ core.Finding) {})
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("expected static asset target to be skipped without any request, got hits=%d", hits)
	}
}
