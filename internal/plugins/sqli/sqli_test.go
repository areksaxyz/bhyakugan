package sqli

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/areksaxyz/bhyakugan/internal/core"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func buildResponse(req *http.Request, status int, body string, redirects int) *http.Response {
	var prev *http.Response
	for i := 0; i < redirects; i++ {
		redirectReq := &http.Request{}
		redirectResp := &http.Response{
			StatusCode: http.StatusFound,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
			Request:    redirectReq,
		}
		redirectReq.Response = prev
		prev = redirectResp
	}
	req.Response = prev
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}
}

func TestCollectBaselineUsesFiveSamples(t *testing.T) {
	var hits int32
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			atomic.AddInt32(&hits, 1)
			return buildResponse(req, http.StatusOK, "baseline ok", 0), nil
		}),
	}
	baseline, bodyLower, err := collectBaseline("http://example.com", client, baselineSampleCount)
	if err != nil {
		t.Fatalf("collectBaseline error: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != baselineSampleCount {
		t.Fatalf("expected %d baseline samples, got %d", baselineSampleCount, got)
	}
	if !baseline.timeDetectionEnabled {
		t.Fatal("expected time detection to stay enabled")
	}
	if baseline.bodyHash == "" {
		t.Fatal("expected baseline body hash to be set")
	}
	if !strings.Contains(bodyLower, "baseline ok") {
		t.Fatalf("unexpected baseline body: %q", bodyLower)
	}
}

func TestCollectBaselineDisablesTimeDetectionOnMultiRedirect(t *testing.T) {
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return buildResponse(req, http.StatusOK, "done", 2), nil
		}),
	}
	baseline, _, err := collectBaseline("http://example.com/r1", client, baselineSampleCount)
	if err != nil {
		t.Fatalf("collectBaseline error: %v", err)
	}
	if baseline.timeDetectionEnabled {
		t.Fatal("expected time detection to be disabled when redirects > 1")
	}
}

func TestCheckTargetTimeGuardRejectsSameBodyHash(t *testing.T) {
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if strings.Contains(strings.ToLower(req.URL.RawQuery), "sleep") {
				time.Sleep(40 * time.Millisecond)
			}
			return buildResponse(req, http.StatusOK, "same-body", 0), nil
		}),
	}
	baselineHash := hashBody([]byte("same-body"))
	baseline := timingBaseline{
		mean:                 0.01,
		stdDev:               0.001,
		bodyHash:             baselineHash,
		timeDetectionEnabled: true,
	}

	var foundCount int32
	var foundMu sync.Mutex
	isAlreadyVulnerable := false
	payload := SQLiPayload{Name: "SQLi Time (Test)", Payload: "sleep(5)", Type: "Time"}
	target := "http://example.com?id=sleep(5)"

	checkTarget(target, payload, client, baseline, "", &isAlreadyVulnerable, &foundMu, func(core.Finding) {
		atomic.AddInt32(&foundCount, 1)
	})
	if atomic.LoadInt32(&foundCount) != 0 {
		t.Fatal("expected no finding because attack body hash equals baseline body hash")
	}
}

func TestComputeZScoreThreshold(t *testing.T) {
	mean, std := 1.0, 0.1
	zLow := computeZScore(1.2, mean, std)
	zHigh := computeZScore(1.5, mean, std)

	if zLow >= timeZScoreThreshold {
		t.Fatalf("expected z-score %.2f to stay below threshold %.2f", zLow, timeZScoreThreshold)
	}
	if zHigh < timeZScoreThreshold {
		t.Fatalf("expected z-score %.2f to be at least threshold %.2f", zHigh, timeZScoreThreshold)
	}
}

func TestScanBooleanBlindDowngradesWhenBodyFingerprintIsWeak(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rawQuery := strings.ToLower(req.URL.RawQuery)
			switch {
			case strings.Contains(rawQuery, "bhyakugan_baseline_control"):
				return buildResponse(req, http.StatusOK, "normal-response", 0), nil
			case strings.Contains(rawQuery, "id=1+and+1%3d1"):
				return buildResponse(req, http.StatusInternalServerError, "normal-response", 0), nil
			case strings.Contains(rawQuery, "id=1+and+1%3d2"):
				return buildResponse(req, http.StatusOK, "normal-response", 0), nil
			default:
				return buildResponse(req, http.StatusOK, "normal-response", 0), nil
			}
		}),
	}

	var findings []core.Finding
	ScanBooleanBlind("http://example.com/search?id=1", client, func(f core.Finding) {
		findings = append(findings, f)
	})

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].Confidence != "probable" {
		t.Fatalf("expected probable confidence, got %q", findings[0].Confidence)
	}
	if findings[0].Severity != "Medium" {
		t.Fatalf("expected Medium severity, got %q", findings[0].Severity)
	}
	if !strings.Contains(strings.ToLower(findings[0].Detail), "manual verification required") {
		t.Fatalf("expected manual-verification note, got detail: %s", findings[0].Detail)
	}
}
