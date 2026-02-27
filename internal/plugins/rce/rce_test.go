package rce

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
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

func TestIsStrongTimeDelaySignal(t *testing.T) {
	controls := []float64{0.4, 0.6}
	attacks := []float64{6.3, 6.1}
	if !isStrongTimeDelaySignal(controls, attacks) {
		t.Fatal("expected strong time delay signal to pass")
	}
}

func TestIsStrongTimeDelaySignalRejectsHighBaseline(t *testing.T) {
	controls := []float64{5.9, 6.2}
	attacks := []float64{7.1, 7.0}
	if isStrongTimeDelaySignal(controls, attacks) {
		t.Fatal("expected high baseline latency to be rejected")
	}
}

func TestConfirmTimeBasedSignalZScorePassesWithDifferentBody(t *testing.T) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			cmd := strings.ToLower(req.URL.Query().Get("cmd"))
			if strings.Contains(cmd, "sleep") {
				time.Sleep(3 * time.Second)
				return buildResponse(req, http.StatusOK, "attack", 0), nil
			}
			return buildResponse(req, http.StatusOK, "control", 0), nil
		}),
	}
	testParams := map[string]string{"cmd": "1"}
	ok, _ := confirmTimeBasedSignal(client, "http://example.com?cmd=1", testParams, "cmd", "sleep 6")
	if !ok {
		t.Fatal("expected strong z-score time signal to pass")
	}
}

func TestConfirmTimeBasedSignalRejectsSameBodyHashNoise(t *testing.T) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			cmd := strings.ToLower(req.URL.Query().Get("cmd"))
			if strings.Contains(cmd, "sleep") {
				time.Sleep(3 * time.Second)
			}
			return buildResponse(req, http.StatusOK, "same-body", 0), nil
		}),
	}
	testParams := map[string]string{"cmd": "1"}
	ok, _ := confirmTimeBasedSignal(client, "http://example.com?cmd=1", testParams, "cmd", "sleep 6")
	if ok {
		t.Fatal("expected signal to be rejected because attack body hash equals baseline body hash")
	}
}

func TestConfirmTimeBasedSignalRedirectGuardRejectsMultiRedirect(t *testing.T) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return buildResponse(req, http.StatusOK, "final", 2), nil
		}),
	}
	testParams := map[string]string{"cmd": "1"}
	ok, _ := confirmTimeBasedSignal(client, "http://example.com/r1?cmd=1", testParams, "cmd", "sleep 6")
	if ok {
		t.Fatal("expected signal to be rejected when redirect count exceeds one")
	}
}

func TestIsUsableHTTPStatusRejectsZero(t *testing.T) {
	if isUsableHTTPStatus(0) {
		t.Fatal("expected HTTP 000/status 0 to be rejected")
	}
}
