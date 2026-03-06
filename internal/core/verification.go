package core

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/yupiyy/bhyakugan/internal/utils"
)

// VerificationResult contains the outcome of a differential analysis
type VerificationResult struct {
	IsConfirmed bool
	Confidence  string
	Detail      string
	Evidence    string
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
	// 1. Establish Baseline (Request with control value)
	baselineTarget, _ := buildTarget(baseURL, param, "bhyakugan_baseline_control")
	baseResp, baseBody, err := ve.performRequest(baselineTarget)
	if err != nil {
		return VerificationResult{IsConfirmed: false, Detail: "Baseline request failed"}
	}
	baseFp := utils.BuildResponseFingerprint(baseResp, []byte(baseBody))
	baseNorm := utils.NormalizeBody(baseBody)
	baseLen := len(baseNorm)

	// 2. Send True Payload
	trueTarget, _ := buildTarget(baseURL, param, truePayload)
	trueResp, trueBody, err := ve.performRequest(trueTarget)
	if err != nil {
		return VerificationResult{IsConfirmed: false, Detail: "True payload request failed"}
	}
	trueFp := utils.BuildResponseFingerprint(trueResp, []byte(trueBody))
	trueNorm := utils.NormalizeBody(trueBody)
	trueLen := len(trueNorm)

	// 3. Send False Payload
	falseTarget, _ := buildTarget(baseURL, param, falsePayload)
	falseResp, falseBody, err := ve.performRequest(falseTarget)
	if err != nil {
		return VerificationResult{IsConfirmed: false, Detail: "False payload request failed"}
	}
	falseFp := utils.BuildResponseFingerprint(falseResp, []byte(falseBody))
	falseNorm := utils.NormalizeBody(falseBody)
	falseLen := len(falseNorm)

	// 4. Analysis & Comparison
	isConfirmed := false
	confidence := "noisy"
	detail := ""
	evidence := fmt.Sprintf("Baseline Len: %d, True Len: %d, False Len: %d", baseLen, trueLen, falseLen)

	// Rule A: Boolean Blind (True matches Baseline, False differs)
	// OR: True differs from Baseline, False matches Baseline (most common for SQLi)
	trueMatchesBase := isSimilar(trueLen, baseLen) && trueResp.StatusCode == baseResp.StatusCode
	falseMatchesBase := isSimilar(falseLen, baseLen) && falseResp.StatusCode == baseResp.StatusCode
	trueFalseDifferent := !isSimilar(trueLen, falseLen) || trueResp.StatusCode != falseResp.StatusCode

	if !trueMatchesBase && falseMatchesBase && trueFalseDifferent {
		isConfirmed = true
		confidence = "confirmed"
		detail = "Boolean differential confirmed: TRUE payload changed response, FALSE payload matched baseline."
	} else if trueMatchesBase && !falseMatchesBase && trueFalseDifferent {
		// Less common but possible depending on logic
		isConfirmed = true
		confidence = "confirmed"
		detail = "Boolean differential confirmed: TRUE payload matched baseline, FALSE payload changed response."
	} else if !trueMatchesBase && !falseMatchesBase && trueFalseDifferent {
		// Both changed baseline, but are different from each other
		isConfirmed = true
		confidence = "probable"
		detail = "Behavioral change confirmed: Both TRUE and FALSE payloads changed response differently from baseline."
	}

	// Anti-FP: If True and False are identical but different from baseline, it's likely just reflection or WAF block
	if !trueMatchesBase && !falseMatchesBase && !trueFalseDifferent {
		isConfirmed = false
		detail = "Potential False Positive: Both TRUE and FALSE payloads produced identical non-baseline responses (likely reflection or WAF)."
	}

	// Extra Check: Redirect/Auth Gate Consistency
	if isConfirmed && utils.IsRedirectAwareIdentical(baseFp, falseFp) && !utils.IsRedirectAwareIdentical(baseFp, trueFp) {
		confidence = "confirmed"
	}

	return VerificationResult{
		IsConfirmed: isConfirmed,
		Confidence:  confidence,
		Detail:      detail,
		Evidence:    evidence,
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
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body), nil
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
	return diff < (len2 / 50) || diff < 15
}
