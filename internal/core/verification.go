package core

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/areksaxyz/bhyakugan/internal/utils"
)

// VerificationResult contains the outcome of a differential analysis
type VerificationResult struct {
	IsConfirmed           bool
	IsSignal              bool
	Confidence            FindingConfidence
	Detail                string
	Evidence              string
	ControlValidated      bool
	ResponseDiffStable    bool
	BodyFingerprintStrong bool
}

// VerificationEngine provides standardized payload validation
type VerificationEngine struct {
	Client *http.Client
}

func NewVerificationEngine(client *http.Client) *VerificationEngine {
	return &VerificationEngine{Client: client}
}

// Verify performs a differential analysis (Baseline vs True vs False)
func (ve *VerificationEngine) Verify(baseURL, param, truePayload, falsePayload string) VerificationResult {
	// 1. Establish controls
	originalProbe, err := ve.requestSnapshot(baseURL)
	if err != nil {
		return VerificationResult{IsConfirmed: false, IsSignal: false, Confidence: ConfidenceNoisy, Detail: "Original request failed"}
	}

	baselineTarget, _ := buildTarget(baseURL, param, "bhyakugan_baseline_control")
	baseProbe, err := ve.requestSnapshot(baselineTarget)
	if err != nil {
		return VerificationResult{IsConfirmed: false, IsSignal: false, Confidence: ConfidenceNoisy, Detail: "Baseline request failed"}
	}

	// 2. Send True Payload
	trueTarget, _ := buildTarget(baseURL, param, truePayload)
	trueProbe, err := ve.requestSnapshot(trueTarget)
	if err != nil {
		return VerificationResult{IsConfirmed: false, IsSignal: false, Confidence: ConfidenceNoisy, Detail: "True payload request failed"}
	}
	trueRepeat, err := ve.requestSnapshot(trueTarget)
	if err != nil {
		return VerificationResult{IsConfirmed: false, IsSignal: false, Confidence: ConfidenceNoisy, Detail: "True payload repeat request failed"}
	}

	// 3. Send False Payload
	falseTarget, _ := buildTarget(baseURL, param, falsePayload)
	falseProbe, err := ve.requestSnapshot(falseTarget)
	if err != nil {
		return VerificationResult{IsConfirmed: false, IsSignal: false, Confidence: ConfidenceNoisy, Detail: "False payload request failed"}
	}
	falseRepeat, err := ve.requestSnapshot(falseTarget)
	if err != nil {
		return VerificationResult{IsConfirmed: false, IsSignal: false, Confidence: ConfidenceNoisy, Detail: "False payload repeat request failed"}
	}

	// 4. Analysis & Comparison
	controlAligned := probesEquivalent(originalProbe, baseProbe)
	trueStable := probesEquivalent(trueProbe, trueRepeat)
	falseStable := probesEquivalent(falseProbe, falseRepeat)
	responseDiffStable := trueStable && falseStable && !probesEquivalent(trueProbe, falseProbe)

	falseMatchesControl := probesEquivalent(falseProbe, baseProbe) || probesEquivalent(falseProbe, originalProbe)
	trueMatchesControl := probesEquivalent(trueProbe, baseProbe) || probesEquivalent(trueProbe, originalProbe)
	bodyFingerprintStrong := responseDiffStable &&
		!probesEquivalent(trueProbe, baseProbe) &&
		!probesEquivalent(trueProbe, originalProbe) &&
		trueProbe.NormalizedBody != falseProbe.NormalizedBody &&
		trueProbe.NormalizedBody != baseProbe.NormalizedBody

	isSignal := responseDiffStable && falseMatchesControl && !trueMatchesControl
	isConfirmed := isSignal && controlAligned && bodyFingerprintStrong

	confidence := ConfidenceNoisy
	detail := "No stable verification differential established."
	switch {
	case isConfirmed:
		confidence = ConfidenceConfirmed
		detail = "Boolean TRUE/FALSE differential confirmed: TRUE payload produced a stable non-baseline response, FALSE payload matched baseline/original control."
	case isSignal:
		confidence = ConfidenceProbable
		detail = "Boolean TRUE/FALSE differential observed, but stable body fingerprint was not established. Manual verification required."
	}

	evidence := fmt.Sprintf(
		"Original Len: %d, Baseline Len: %d, True Len: %d, False Len: %d | control_validation=%t | response_diff_stable=%t | body_fingerprint=%t",
		len(originalProbe.NormalizedBody), len(baseProbe.NormalizedBody), len(trueProbe.NormalizedBody), len(falseProbe.NormalizedBody),
		controlAligned && falseMatchesControl, responseDiffStable, bodyFingerprintStrong,
	)

	return VerificationResult{
		IsConfirmed:           isConfirmed,
		IsSignal:              isSignal,
		Confidence:            confidence,
		Detail:                detail,
		Evidence:              evidence,
		ControlValidated:      controlAligned && falseMatchesControl,
		ResponseDiffStable:    responseDiffStable,
		BodyFingerprintStrong: bodyFingerprintStrong,
	}
}

func (ve *VerificationEngine) performRequest(target string) (*http.Response, string, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, "", err
	}
	utils.SetDefaultHeaders(req, target)
	resp, err := ve.Client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
	return resp, string(body), nil
}

type verificationProbe struct {
	StatusCode     int
	NormalizedBody string
	Fingerprint    utils.ResponseFingerprint
}

func (ve *VerificationEngine) requestSnapshot(target string) (verificationProbe, error) {
	resp, body, err := ve.performRequest(target)
	if err != nil {
		return verificationProbe{}, err
	}
	return verificationProbe{
		StatusCode:     resp.StatusCode,
		NormalizedBody: utils.NormalizeBody(body),
		Fingerprint:    utils.BuildResponseFingerprint(resp, []byte(body)),
	}, nil
}

func buildTarget(baseURL, param, value string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL, err
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func isSimilar(len1, len2 int) bool {
	if len1 == 0 || len2 == 0 {
		return len1 == len2
	}
	diff := len1 - len2
	if diff < 0 {
		diff = -diff
	}
	// 2% tolerance for large pages or 15 bytes for small ones
	return diff < (len2/50) || diff < 15
}

func responsesEquivalent(statusA int, fpA utils.ResponseFingerprint, bodyA string, statusB int, fpB utils.ResponseFingerprint, bodyB string) bool {
	if statusA != statusB {
		return false
	}
	if utils.IsRedirectAwareIdentical(fpA, fpB) {
		return true
	}
	if bodyA == bodyB {
		return true
	}
	return false
}

func probesEquivalent(a, b verificationProbe) bool {
	return responsesEquivalent(a.StatusCode, a.Fingerprint, a.NormalizedBody, b.StatusCode, b.Fingerprint, b.NormalizedBody)
}
