package output

import (
	"fmt"
	"html/template"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/areksaxyz/bhyakugan/internal/core"
	"github.com/areksaxyz/bhyakugan/internal/scanner"
)

func cleanEndpoint(urlStr string) string {
	if idx := strings.Index(urlStr, "?"); idx != -1 {
		return urlStr[:idx]
	}
	return urlStr
}

func escapeHTML(s string) string {
	return template.HTMLEscapeString(s)
}

func isSafeReportURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}

	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

func buildReportLink(rawURL, display string) string {
	escapedDisplay := escapeHTML(display)
	if !isSafeReportURL(rawURL) {
		return escapedDisplay
	}

	return fmt.Sprintf(`<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>`, escapeHTML(rawURL), escapedDisplay)
}

func createPrivateFile(filename string) (*os.File, error) {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func GenerateHTML(filename string, rawFindings []core.Finding, liveHosts []string, target, mode string) error {
	f, err := createPrivateFile(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	runtimeMode := scanner.NormalizeRuntimeMode(mode)

	normalizedRaw := normalizeReportFindings(rawFindings)
	validatedRaw, _, _ := partitionReportFindings(normalizedRaw)

	// Impact per Endpoint (Priority 4 - Refactored: Canonical & Conflict Resolution)
	endpointImpacts := make(map[string]map[string]bool)
	endpointTypes := make(map[string]string) // Track detected backend type (SQL vs NoSQL)

	for _, f := range validatedRaw {
		if f.Severity == "Critical" || f.Severity == "High" {
			ep := cleanEndpoint(f.Target)
			if _, ok := endpointImpacts[ep]; !ok {
				endpointImpacts[ep] = make(map[string]bool)
			}

			// Detect Backend Conflict
			isNoSQL := strings.Contains(f.Type, "NoSQL")
			isSQLi := strings.Contains(f.Type, "SQL Injection")

			if isNoSQL {
				if endpointTypes[ep] == "SQL" {
					continue
				} // Skip NoSQL if already confirmed SQL (rare)
				endpointTypes[ep] = "NoSQL"
				endpointImpacts[ep]["Authentication Logic Bypass (NoSQL)"] = true
			} else if isSQLi {
				if endpointTypes[ep] == "NoSQL" {
					continue
				} // Skip SQLi if already confirmed NoSQL
				endpointTypes[ep] = "SQL"
				endpointImpacts[ep]["Database Interaction Control (SQLi)"] = true
			} else {
				// Other types don't conflict
				if strings.Contains(f.Type, "LFI") || strings.Contains(f.Type, "Path Traversal") {
					endpointImpacts[ep]["Arbitrary File Read (LFI)"] = true
				}
				if strings.Contains(f.Type, "Secret Leak") {
					endpointImpacts[ep]["Credential Exposure (Secrets)"] = true
				}
				if strings.Contains(f.Type, "RCE") {
					endpointImpacts[ep]["Remote Code Execution (RCE)"] = true
				}
				if strings.Contains(f.Type, "SSRF") {
					endpointImpacts[ep]["Internal Infrastructure Access (SSRF)"] = true
				}
			}
		}
	}

	// Consolidate Findings for Display
	findings := normalizeReportFindings(consolidateFindings(rawFindings))
	validatedFindings, probableSignals, observations := partitionReportFindings(findings)

	sortReportFindings(validatedFindings)
	sortReportFindings(probableSignals)
	sortReportFindings(observations)

	overviewCounts := map[core.FindingBucket]int{
		core.BucketValidated: len(validatedFindings),
		core.BucketProbable:  len(probableSignals),
		core.BucketRecon:     len(observations),
	}
	validatedSeverityStats := make(map[string]int)
	for _, sev := range []string{"Critical", "High", "Medium", "Low"} {
		validatedSeverityStats[sev] = 0
	}
	for _, fnd := range validatedFindings {
		sev := normalizeSeverityLabel(fnd.Severity)
		if _, ok := validatedSeverityStats[sev]; ok {
			validatedSeverityStats[sev]++
		}
	}
	validatedScopeCount := countUniqueExploitable(normalizedRaw)

	// CSS & Header (Same as before)
	htmlHead := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bhyakugan Report - %s</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
            --primary-glow: rgba(56, 189, 248, 0.2);
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #10b981;
            --info: #0ea5e9;
            --border: #334155;
        }

        * { box-sizing: border-box; transition: all 0.2s ease; }
        body { 
            font-family: 'Inter', system-ui, -apple-system, sans-serif; 
            background-color: var(--bg-color); 
            color: var(--text-main); 
            margin: 0; 
            padding: 20px; 
            line-height: 1.5;
        }

        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }

        /* Header Area */
        .header { 
            background: linear-gradient(135deg, #1e293b 0%%, #0f172a 100%%);
            padding: 40px; 
            border-radius: 16px; 
            border: 1px solid var(--border);
            margin-bottom: 30px; 
            display: flex; 
            justify-content: space-between; 
            align-items: center;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
        }
        .header h1 { 
            margin: 0; 
            font-size: 2.5rem; 
            font-weight: 800; 
            background: linear-gradient(to right, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -1px;
        }
        .header-meta { text-align: right; color: var(--text-muted); font-size: 0.9rem; line-height: 1.8; }
        .header-meta strong { color: var(--text-main); }

        /* Dashboard Stats */
        .dashboard { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .card { 
            background: var(--card-bg); 
            padding: 24px; 
            border-radius: 12px; 
            border: 1px solid var(--border);
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        .card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 4px;
        }
        .card h3 { margin: 0; font-size: 2.5rem; font-weight: 800; }
        .card p { margin: 8px 0 0; color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 1px; }
        
        .card.exposure::before { background: var(--critical); } .card.exposure h3 { color: var(--critical); }
        .card.signal::before { background: var(--medium); } .card.signal h3 { color: var(--medium); }
        .card.recon::before { background: var(--info); } .card.recon h3 { color: var(--info); }
        .card.hosts::before { background: var(--primary); } .card.hosts h3 { color: var(--primary); }
        .card.critical::before { background: var(--critical); } .card.critical h3 { color: var(--critical); }
        .card.high::before { background: var(--high); } .card.high h3 { color: var(--high); }
        .card.medium::before { background: var(--medium); } .card.medium h3 { color: var(--medium); }
        .card.low::before { background: var(--low); } .card.low h3 { color: var(--low); }
        .card.info::before { background: var(--info); } .card.info h3 { color: var(--info); }
        .dashboard-title {
            margin: 0 0 14px 2px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.8rem;
            font-weight: 700;
        }

        /* Impact Summary (Scoped) */
        .impact-summary { 
            background: rgba(56, 189, 248, 0.05);
            border: 1px solid rgba(56, 189, 248, 0.2);
            padding: 30px; 
            border-radius: 12px; 
            margin-bottom: 40px; 
        }
        .impact-summary h2 { 
            margin-top: 0; 
            font-size: 1.1rem; 
            color: var(--primary); 
            text-transform: uppercase; 
            letter-spacing: 1px;
            margin-bottom: 20px;
        }
        .impact-group { margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 15px; }
        .impact-group:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
        .impact-group h3 { font-size: 0.95rem; margin: 0 0 10px 0; color: var(--text-main); font-family: monospace; }
        .impact-list { display: flex; flex-wrap: wrap; gap: 12px; }
        .impact-item { 
            background: #1e293b; 
            border: 1px solid var(--critical);
            padding: 6px 12px; 
            border-radius: 6px;
            font-size: 0.8rem; 
            font-weight: 700;
            color: var(--critical);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }

        /* Findings Tables */
        .section-title { 
            font-size: 1.25rem; 
            font-weight: 700;
            margin: 50px 0 20px; 
            display: flex; 
            align-items: center;
        }
        .section-badge { 
            padding: 4px 12px; 
            border-radius: 6px; 
            font-size: 0.75rem; 
            font-weight: 800; 
            color: #fff; 
            margin-right: 12px;
            text-transform: uppercase;
        }
        
        .table-container { 
            background: var(--card-bg); 
            border-radius: 12px; 
            border: 1px solid var(--border);
            overflow: hidden; 
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        table { width: 100%%; border-collapse: collapse; }
        th { 
            background: rgba(15, 23, 42, 0.5); 
            color: var(--text-muted); 
            text-transform: uppercase; 
            font-size: 0.7rem; 
            letter-spacing: 1px; 
            padding: 16px 24px; 
            text-align: left; 
            border-bottom: 1px solid var(--border);
        }
        td { padding: 20px 24px; vertical-align: top; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(255, 255, 255, 0.02); }
        
	        .col-type { width: 18%%; font-weight: 700; color: var(--primary); }
	        .col-target { width: 24%%; word-break: break-all; }
            .col-severity { width: 8%%; }
	        .col-score { width: 10%%; font-weight: 700; }
	        .col-detail { width: 32%%; color: var(--text-muted); font-size: 0.85rem; line-height: 1.6; white-space: pre-wrap; }
        .col-detail code { background: #0f172a; padding: 2px 4px; border-radius: 4px; color: #38bdf8; font-family: monospace; }
        
        .bg-Critical { background: var(--critical); }
        .bg-High { background: var(--high); }
        .bg-Medium { background: var(--medium); }
        .bg-Low { background: var(--low); }
        .bg-Info { background: var(--info); }
        
        a { color: var(--primary); text-decoration: none; font-weight: 500; }
        a:hover { text-decoration: underline; }

        @media (max-width: 768px) {
            .header { flex-direction: column; text-align: center; padding: 30px; }
            .header-meta { text-align: center; margin-top: 20px; }
            .col-type, .col-target, .col-detail { width: auto; display: block; padding: 10px 0; }
            th { display: none; }
            td { padding: 20px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>Bhyakugan Report</h1>
                <p style="margin: 8px 0 0 0; color: var(--text-muted); font-weight: 500;">Public Exposure and Recon Outcome</p>
            </div>
            <div class="header-meta">
                <p>Target: %s</p>
                <p>Mode: <strong>%s</strong></p>
                <p>Date: <strong>%s</strong></p>
                <p>Validated Scope Count: <strong>%d</strong></p>
            </div>
        </div>

        <div class="dashboard-title">Exposure Overview</div>
        <div class="dashboard">
            <div class="card exposure"><h3>%d</h3><p>Validated Exposures</p></div>
            <div class="card signal"><h3>%d</h3><p>Probable Sensitive Signals</p></div>
            <div class="card recon"><h3>%d</h3><p>Recon Surfaces</p></div>
            <div class="card hosts"><h3>%d</h3><p>Live Hosts</p></div>
        </div>

        <div class="dashboard-title">Validated Severity</div>
        <div class="dashboard">
            <div class="card critical"><h3>%d</h3><p>Critical</p></div>
            <div class="card high"><h3>%d</h3><p>High</p></div>
            <div class="card medium"><h3>%d</h3><p>Medium</p></div>
            <div class="card low"><h3>%d</h3><p>Low</p></div>
        </div>
`, escapeHTML(target), buildReportLink(target, target), escapeHTML(runtimeMode), time.Now().Format("Jan 02, 2006 15:04:05 MST"), validatedScopeCount, overviewCounts[core.BucketValidated], overviewCounts[core.BucketProbable], overviewCounts[core.BucketRecon], len(liveHosts), validatedSeverityStats["Critical"], validatedSeverityStats["High"], validatedSeverityStats["Medium"], validatedSeverityStats["Low"])

	if _, err := f.WriteString(htmlHead); err != nil {
		return err
	}

	// Render Impact Summary
	if len(endpointImpacts) > 0 {
		f.WriteString(`<div class="impact-summary"><h2>Validated Exposure Impact by Endpoint:</h2>`)
		for endpoint, imps := range endpointImpacts {
			f.WriteString(fmt.Sprintf(`<div class="impact-group"><h3>%s</h3><div class="impact-list">`, escapeHTML(endpoint)))
			for imp := range imps {
				f.WriteString(fmt.Sprintf(`<div class="impact-item">%s</div>`, escapeHTML(imp)))
			}
			f.WriteString(`</div></div>`)
		}
		f.WriteString(`</div>`)
	}

	if err := renderFindingSection(f, core.BucketValidated, validatedFindings, true); err != nil {
		return err
	}
	if err := renderFindingSection(f, core.BucketProbable, probableSignals, true); err != nil {
		return err
	}
	if err := renderFindingSection(f, core.BucketRecon, observations, false); err != nil {
		return err
	}

	// Footer
	footer := `
        <div style="text-align: center; margin-top: 50px; padding: 20px; color: #b2bec3; font-size: 0.9rem;">
            Generated by <strong>Bhyakugan Scanner</strong> • Automated Security Analysis
        </div>
    </div></body></html>`

	if _, err := f.WriteString(footer); err != nil {
		return err
	}

	return nil
}

func SaveList(filename string, items []string) error {
	f, err := createPrivateFile(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, item := range items {
		if _, err := f.WriteString(item + "\n"); err != nil {
			return err
		}
	}
	return nil
}

func normalizeReportFindings(findings []core.Finding) []core.Finding {
	out := make([]core.Finding, 0, len(findings))
	for _, f := range findings {
		out = append(out, normalizeReportFinding(f))
	}
	return out
}

func normalizeReportFinding(f core.Finding) core.Finding {
	f.Severity = normalizeSeverityLabel(f.Severity)
	f.Confidence = f.Confidence.Normalized()

	lowerType := strings.ToLower(strings.TrimSpace(f.Type))
	lowerDetail := strings.ToLower(strings.TrimSpace(f.Detail))

	if strings.Contains(lowerDetail, "validation status: informational signal only") ||
		strings.Contains(lowerDetail, "no deterministic boolean/count/error proof") {
		f.Severity = "Info"
		f.Confidence = core.ConfidenceNoisy
		return f
	}

	if (strings.Contains(lowerDetail, "manual verification required") || strings.Contains(lowerDetail, "needs manual verification")) &&
		severityRank(f.Severity) > severityRank("Medium") {
		f.Severity = "Medium"
	}

	if isBooleanBasedSQLSignal(f) && strings.Contains(lowerDetail, "body_fingerprint=false") {
		if f.Confidence == core.ConfidenceConfirmed {
			f.Confidence = core.ConfidenceProbable
		}
		if severityRank(f.Severity) > severityRank("Medium") {
			f.Severity = "Medium"
		}
	}

	if strings.Contains(lowerType, "xpath injection") && isXPathInformationalReportSignal(lowerDetail) {
		f.Severity = "Info"
		f.Confidence = core.ConfidenceNoisy
		return f
	}

	if !isReconObservation(f) && f.Confidence == core.ConfidenceConfirmed && !hasValidatedEvidence(f) {
		f.Confidence = core.ConfidenceProbable
		if severityRank(f.Severity) > severityRank("Medium") {
			f.Severity = "Medium"
		}
	}

	return f
}

func partitionReportFindings(findings []core.Finding) (validated, signals, observations []core.Finding) {
	validated = make([]core.Finding, 0, len(findings))
	signals = make([]core.Finding, 0, len(findings))
	observations = make([]core.Finding, 0, len(findings))

	for _, f := range findings {
		switch reportFindingBucket(f) {
		case core.BucketRecon:
			observations = append(observations, f)
		case core.BucketValidated:
			validated = append(validated, f)
		default:
			signals = append(signals, f)
		}
	}

	return validated, signals, observations
}

func hasValidatedEvidence(f core.Finding) bool {
	lowerDetail := strings.ToLower(strings.TrimSpace(f.Detail))
	if strings.Contains(lowerDetail, "manual verification required") ||
		strings.Contains(lowerDetail, "needs manual verification") ||
		strings.Contains(lowerDetail, "validation status: informational signal only") ||
		strings.Contains(lowerDetail, "no deterministic boolean/count/error proof") {
		return false
	}

	score, hasScore := scanner.ExtractEvidenceQualityScore(f.Detail)
	if hasScore && score < 80 {
		return false
	}

	if isBooleanBasedSQLSignal(f) && strings.Contains(lowerDetail, "body_fingerprint=false") {
		return false
	}

	if depth, ok := scanner.ExtractExploitDepth(f.Detail); ok && depth < 3 {
		return false
	}

	return severityRank(f.Severity) >= severityRank("High")
}

func isValidatedFinding(f core.Finding) bool {
	if isReconObservation(f) {
		return false
	}
	if f.Confidence.Normalized() != core.ConfidenceConfirmed {
		return false
	}
	return hasValidatedEvidence(f)
}

func isBooleanBasedSQLSignal(f core.Finding) bool {
	lowerType := strings.ToLower(strings.TrimSpace(f.Type))
	lowerDetail := strings.ToLower(strings.TrimSpace(f.Detail))
	return strings.Contains(lowerType, "sql injection") && strings.Contains(lowerDetail, "boolean")
}

func isXPathInformationalReportSignal(detail string) bool {
	return strings.Contains(detail, "validation status: informational signal only") ||
		(strings.Contains(detail, "heuristic only") &&
			!strings.Contains(detail, "boolean true/false differential confirmed") &&
			!strings.Contains(detail, "count() differential confirmed") &&
			!strings.Contains(detail, "structural xml leak detected"))
}

func reportFindingBucket(f core.Finding) core.FindingBucket {
	switch {
	case isReconObservation(f):
		return core.BucketRecon
	case isValidatedFinding(f):
		return core.BucketValidated
	default:
		return core.BucketProbable
	}
}

func sortReportFindings(findings []core.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri := severityRank(findings[i].Severity)
		rj := severityRank(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}

		ci := core.ConfidenceRank(findings[i].Confidence)
		cj := core.ConfidenceRank(findings[j].Confidence)
		if ci != cj {
			return ci > cj
		}

		si := exploitabilityScore(findings[i])
		sj := exploitabilityScore(findings[j])
		if si != sj {
			return si > sj
		}

		if findings[i].Type != findings[j].Type {
			return findings[i].Type < findings[j].Type
		}
		return findings[i].Target < findings[j].Target
	})
}

func renderFindingSection(out *os.File, bucket core.FindingBucket, items []core.Finding, includeExploitability bool) error {
	if len(items) == 0 {
		return nil
	}

	title := core.DisplayBucketLabel(bucket)
	badge := bucketBadgeSeverity(bucket)
	exploitabilityHeader := ""
	if includeExploitability {
		exploitabilityHeader = `<th class="col-score">Exploitability</th>`
	}

	sectionHeader := fmt.Sprintf(`
        <div class="section-title">
            <span class="section-badge bg-%s">%s</span> (%d)
        </div>
        <div class="table-container">
            <table>
                <thead><tr><th class="col-type">Type</th><th class="col-target">Target</th><th class="col-severity">Severity</th><th>Confidence</th>%s<th class="col-detail">Evidence / Details</th></tr></thead>
                <tbody>`, badge, title, len(items), exploitabilityHeader)
	if _, err := out.WriteString(sectionHeader); err != nil {
		return err
	}

	for _, item := range items {
		displayTarget := cleanEndpoint(item.Target)
		if strings.Contains(item.Target, "Endpoints Detected") {
			displayTarget = item.Target
		}
		targetCell := buildReportLink(item.Target, displayTarget)
		severityCell := fmt.Sprintf(`<span class="section-badge bg-%s">%s</span>`, normalizeSeverityLabel(item.Severity), normalizeSeverityLabel(item.Severity))

		exploitabilityCell := ""
		if includeExploitability {
			exploitabilityCell = fmt.Sprintf(`<td class="col-score">%d/100</td>`, exploitabilityScore(item))
		}

		row := fmt.Sprintf(`
            <tr>
                <td class="col-type">%s</td>
                <td class="col-target">%s</td>
                <td class="col-severity">%s</td>
                <td>%s</td>
                %s
                <td class="col-detail">%s</td>
            </tr>`,
			escapeHTML(displayFindingType(item)),
			targetCell,
			severityCell,
			escapeHTML(item.Confidence.DisplayLabel()),
			exploitabilityCell,
			escapeHTML(item.Detail),
		)
		if _, err := out.WriteString(row); err != nil {
			return err
		}
	}

	_, err := out.WriteString("</tbody></table></div>")
	return err
}

func bucketBadgeSeverity(bucket core.FindingBucket) string {
	switch bucket {
	case core.BucketValidated:
		return "High"
	case core.BucketRecon:
		return "Info"
	default:
		return "Medium"
	}
}

func displayFindingType(f core.Finding) string {
	switch {
	case strings.EqualFold(f.Type, "Path Discovered"), strings.EqualFold(f.Type, "Accessible Path"):
		return "Surface Discovery"
	case strings.EqualFold(f.Type, "Recon: Login Form Detected"):
		return "Auth Surface: Login Form"
	default:
		return f.Type
	}
}

func isReconObservation(f core.Finding) bool {
	sev := normalizeSeverityLabel(f.Severity)
	if sev == "Critical" || sev == "High" {
		return false
	}

	lowerType := strings.ToLower(strings.TrimSpace(f.Type))
	lowerDetail := strings.ToLower(strings.TrimSpace(f.Detail))

	if strings.Contains(lowerDetail, "tier=tier3") {
		return true
	}
	if isExplicitReconType(lowerType) {
		return true
	}

	conf := f.Confidence.Normalized()
	if (sev == "Info" || sev == "Low") && conf == core.ConfidenceNoisy {
		if !strings.Contains(lowerDetail, "deterministic=true") || !strings.Contains(lowerDetail, "control_validation=true") {
			return true
		}
	}

	return strings.Contains(lowerDetail, "informational signal only") ||
		strings.Contains(lowerDetail, "no exploitation confirmed") ||
		strings.Contains(lowerDetail, "configuration exposure only") ||
		strings.Contains(lowerDetail, "policy misconfiguration signal only")
}

func isExplicitReconType(t string) bool {
	if strings.HasPrefix(t, "recon:") {
		return true
	}

	reconMarkers := []string{
		"path discovered",
		"auth-gated endpoint",
		"websocket endpoint",
		"graphql endpoint",
		"graphql interface",
		"graphql endpoints detected",
		"graphql introspection",
		"graphql batching",
		"graphql schema discovery exposure",
		"jwt discovered",
		"jwt header info",
		"jwt sensitive info",
		"object reference surface",
		"saml endpoints detected",
		"mobile-specific endpoint",
	}
	for _, marker := range reconMarkers {
		if strings.Contains(t, marker) {
			return true
		}
	}
	return false
}

func consolidateFindings(findings []core.Finding) []core.Finding {
	var consolidated []core.Finding

	// Map to group findings
	// Key format varies by severity to support different consolidation strategies
	grouped := make(map[string][]core.Finding)
	rootCauseSignatureCounts := make(map[string]int)
	materialRootCauseClassSeen := make(map[string]bool)

	normalized := make([]core.Finding, 0, len(findings))
	for _, f := range findings {
		fType := f.Type
		if fType == "Hidden Directory" || fType == "Protected Directory" {
			fType = "Accessible Path"
		}
		if fType == "GraphQL Endpoint" || fType == "GraphQL Interface" {
			fType = "GraphQL Endpoint Discovery"
		}
		if fType == "Database Dump Exposed" || fType == "Sensitive Config Exposed" {
			fType = "Sensitive Config/Backup Exposed"
		}
		if fType == "Critical Data Leak in Path" || fType == "Secret Leak" {
			fType = "Sensitive Data Exposure"
		}
		f.Type = fType
		normalized = append(normalized, f)
		if class := scanner.NormalizedVulnerabilityClass(f); shouldSuppressWeakDuplicateRootCause(class, normalizeSeverityLabel(f.Severity)) {
			materialRootCauseClassSeen[class] = true
		}

		if sig := rootCauseCollapseSignature(f); sig != "" {
			rootCauseSignatureCounts[sig]++
		}
	}

	for _, f := range normalized {
		fType := f.Type
		if class := scanner.NormalizedVulnerabilityClass(f); materialRootCauseClassSeen[class] && isWeakDuplicateRootCauseFinding(class, normalizeSeverityLabel(f.Severity)) {
			continue
		}

		var key string
		if f.Severity == "Critical" || f.Severity == "High" {
			// Strategy: Root-cause scope consolidation for exploit-grade findings.
			clusterType := highSeverityClusterType(f)
			ep := cleanEndpoint(f.Target)
			scopeKey, scopeLabel := highSeverityScope(clusterType, ep)
			// Keep one unique issue per type+scope regardless of High/Critical split.
			key = fmt.Sprintf("%s|%s|%s", clusterType, scopeKey, scopeLabel)
		} else if sig := rootCauseCollapseSignature(f); sig != "" && rootCauseSignatureCounts[sig] > 3 {
			// Root-cause collapsing engine for noisy repeated medium/low/info findings.
			key = "ROOTCAUSE::" + sig
		} else {
			// Strategy: Global Consolidation for Noise Reduction
			// We want to group widespread low-impact issues (e.g. Missing Headers on 50 pages).
			// Key: Type | Severity
			key = fmt.Sprintf("%s|%s", fType, f.Severity)
		}

		grouped[key] = append(grouped[key], f)
	}

	for key, group := range grouped {
		if strings.HasPrefix(key, "ROOTCAUSE::") {
			signature := strings.TrimPrefix(key, "ROOTCAUSE::")
			clusterLabel := rootCauseDisplayLabel(signature, group[0].Type)
			detail := buildConciseRootCauseClusterDetail(group)

			consolidated = append(consolidated, core.Finding{
				Type:       clusterLabel,
				Target:     fmt.Sprintf("%d Endpoints Detected", countUniqueTargets(group)),
				Detail:     detail,
				Severity:   maxSeverityInGroup(group),
				Confidence: bestConfidenceInGroup(group),
			})
			continue
		}

		parts := strings.SplitN(key, "|", 3)
		fType := parts[0]
		fSeverity := ""
		scopeLabel := ""
		if len(parts) == 3 {
			scopeLabel = parts[2]
			fSeverity = maxSeverityInGroup(group)
		} else if len(parts) == 2 {
			fSeverity = parts[1]
		} else if len(group) > 0 {
			fSeverity = group[0].Severity
		}

		// --- HANDLING CRITICAL / HIGH ---
		if fSeverity == "Critical" || fSeverity == "High" {
			// Always render as a cluster object (including singletons) to keep
			// consistent root-cause style output and include original signatures.
			displayTarget := cleanEndpoint(group[0].Target)
			if strings.TrimSpace(scopeLabel) != "" {
				displayTarget = scopeLabel
			}

			typeSeen := make(map[string]bool)
			typeList := make([]string, 0, len(group))
			for _, g := range group {
				if !typeSeen[g.Type] {
					typeSeen[g.Type] = true
					typeList = append(typeList, g.Type)
				}
			}

			detail := buildConciseHighSeverityClusterDetail(group, typeList)

			consolidated = append(consolidated, core.Finding{
				Type:       fType,
				Target:     displayTarget,
				Detail:     detail,
				Severity:   fSeverity,
				Confidence: bestConfidenceInGroup(group),
			})
			continue
		}

		// --- HANDLING MEDIUM / LOW / INFO ---

		autoConsolidateLowSignal := len(group) > 1 && (fSeverity == "Info" || fSeverity == "Low")
		shouldConsolidate := autoConsolidateLowSignal || (len(group) > 1 && (strings.Contains(fType, "Web Cache") ||
			strings.Contains(fType, "ORM Leak") ||
			strings.Contains(fType, "S3 Bucket") ||
			strings.Contains(fType, "SQL Injection") ||
			fType == "Directory Listing Enabled" ||
			fType == "Vulnerability" ||
			fType == "XSLT Injection" ||
			fType == "XPath Injection" ||
			strings.Contains(fType, "Improper Trust in HTTP Headers (Proxy Bypass)") ||
			strings.Contains(fType, "Cross-Site WebSocket Hijacking") ||
			fType == "GraphQL Endpoint" ||
			fType == "GraphQL Interface" ||
			fType == "GraphQL Endpoint Discovery" ||
			fType == "GraphQL Introspection" ||
			fType == "GraphQL Batching" ||
			fType == "JWT Header Info" ||
			strings.Contains(fType, "SAML") ||
			fType == "Path Discovered" ||
			fType == "Accessible Path" ||
			fType == "Mobile-Specific Endpoint"))

		if shouldConsolidate {
			// Special handling for SAML Info
			if strings.Contains(fType, "SAML") {
				consolidated = append(consolidated, core.Finding{
					Type:     "SAML Endpoints Detected",
					Target:   fmt.Sprintf("%d Endpoints Detected", len(group)),
					Detail:   "SAML endpoints identified during reconnaissance. No exploitation confirmed. Informational only.",
					Severity: fSeverity,
				})
				continue
			}

			// Special handling for GraphQL endpoint discovery (keep vulnerability types separate)
			if fType == "GraphQL Endpoint" || fType == "GraphQL Interface" || fType == "GraphQL Endpoint Discovery" {
				consolidated = append(consolidated, core.Finding{
					Type:     "GraphQL Endpoints Detected",
					Target:   fmt.Sprintf("%d Endpoints Detected", len(group)),
					Detail:   "GraphQL endpoints detected across multiple paths. No introspection or schema leak confirmed.",
					Severity: fSeverity,
				})
				continue
			}

			var detailsBuilder strings.Builder
			detailsBuilder.WriteString(fmt.Sprintf("Issue observed across %d endpoints.\n\nCombined Evidence:\n", len(group)))

			for _, f := range group {
				cleanDetail := strings.ReplaceAll(f.Detail, "\n", " ")
				detailsBuilder.WriteString(fmt.Sprintf("- %s  [%s]\n", f.Target, cleanDetail))
			}

			consolidated = append(consolidated, core.Finding{
				Type:       fType,
				Target:     fmt.Sprintf("%d Endpoints Detected", len(group)),
				Detail:     detailsBuilder.String(),
				Severity:   fSeverity,
				Confidence: bestConfidenceInGroup(group),
			})
		} else {
			consolidated = append(consolidated, group...)
		}
	}

	return consolidated
}

func rootCauseCollapseSignature(f core.Finding) string {
	class := scanner.NormalizedVulnerabilityClass(f)
	if class == "" {
		return ""
	}

	eligible := map[string]bool{
		"xml_query_injection":                           true,
		"template_engine_injection":                     true,
		"websocket_origin_policy_misconfiguration":      true,
		"graphql_introspection":                         true,
		"improper_trust_in_http_headers_(proxy_bypass)": true,
	}
	if !eligible[class] {
		return ""
	}

	proof := extractMeaningfulProofLine(f.Detail)
	if class == "xml_query_injection" || class == "template_engine_injection" {
		proof = class
	} else if proof == "" {
		proof = scanner.ExecutionProofSignature(f.Detail)
	}
	if proof == "" {
		proof = "none"
	}
	return class + "|" + proof + "|" + middlewareSignature(f.Detail)
}

func shouldSuppressWeakDuplicateRootCause(class, severity string) bool {
	switch class {
	case "xml_query_injection", "template_engine_injection":
		return severityRank(normalizeSeverityLabel(severity)) >= severityRank("Medium")
	default:
		return false
	}
}

func isWeakDuplicateRootCauseFinding(class, severity string) bool {
	switch class {
	case "xml_query_injection", "template_engine_injection":
		return severityRank(normalizeSeverityLabel(severity)) < severityRank("Medium")
	default:
		return false
	}
}

func rootCauseDisplayLabel(signature, fallback string) string {
	switch {
	case strings.Contains(signature, "xml_query_injection"):
		return "XML Query Injection"
	case strings.Contains(signature, "template_engine_injection"):
		return "Template Engine Injection"
	case strings.Contains(signature, "websocket_origin_policy_misconfiguration"):
		return "WebSocket Origin Policy Misconfiguration"
	case strings.Contains(signature, "graphql_introspection"):
		return "GraphQL Schema Discovery Exposure"
	case strings.Contains(signature, "improper_trust_in_http_headers_(proxy_bypass)"):
		return "Improper Trust in Proxy Headers"
	default:
		return fallback
	}
}

func middlewareSignature(detail string) string {
	d := strings.ToLower(detail)
	switch {
	case strings.Contains(d, "laravel"):
		return "laravel"
	case strings.Contains(d, "django"):
		return "django"
	case strings.Contains(d, "express"), strings.Contains(d, "node"):
		return "node"
	case strings.Contains(d, "spring"), strings.Contains(d, "java"):
		return "spring"
	case strings.Contains(d, "asp.net"), strings.Contains(d, "iis"):
		return "aspnet"
	case strings.Contains(d, "libxslt"):
		return "libxslt"
	case strings.Contains(d, "graphql"):
		return "graphql"
	case strings.Contains(d, "proxy"), strings.Contains(d, "header"):
		return "proxy"
	default:
		return "unknown"
	}
}

func countUniqueTargets(group []core.Finding) int {
	return len(uniqueTargetList(group))
}

func uniqueTargetList(group []core.Finding) []string {
	seen := make(map[string]bool, len(group))
	targets := make([]string, 0, len(group))
	for _, g := range group {
		ep := cleanEndpoint(strings.TrimSpace(g.Target))
		if ep == "" || seen[ep] {
			continue
		}
		seen[ep] = true
		targets = append(targets, ep)
	}
	sort.Strings(targets)
	return targets
}

func representativeProofLines(group []core.Finding, limit int) []string {
	if limit <= 0 {
		return nil
	}
	type candidate struct {
		target string
		proof  string
	}
	picked := make([]candidate, 0, limit)
	seen := make(map[string]bool)
	for _, g := range group {
		proof := extractMeaningfulProofLine(g.Detail)
		if proof == "" {
			proof = scanner.ExecutionProofSignature(g.Detail)
		}
		if proof == "" || proof == "none" {
			proof = "behavior-change signal"
		}
		key := g.Type + "|" + proof
		if seen[key] {
			continue
		}
		seen[key] = true
		picked = append(picked, candidate{
			target: cleanEndpoint(g.Target),
			proof:  proof,
		})
		if len(picked) >= limit {
			break
		}
	}

	lines := make([]string, 0, len(picked))
	for i, p := range picked {
		lines = append(lines, fmt.Sprintf("%d. endpoint=%s proof=%s", i+1, p.target, p.proof))
	}
	return lines
}

func buildConciseRootCauseClusterDetail(group []core.Finding) string {
	targets := uniqueTargetList(group)
	reps := representativeProofLines(group, 3)
	params := collectAffectedParameters(group)
	policyNotes := collectPolicyNotes(group)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Root-cause collapse applied across %d related signals.\n", len(group)))
	b.WriteString(fmt.Sprintf("Affected endpoints: %d\n", len(targets)))
	if len(params) > 0 {
		b.WriteString(fmt.Sprintf("Affected parameters: %s\n", strings.Join(params, ", ")))
	}

	maxTargets := len(targets)
	if maxTargets > 8 {
		maxTargets = 8
	}
	for i := 0; i < maxTargets; i++ {
		b.WriteString(fmt.Sprintf("- %s\n", targets[i]))
	}
	if len(targets) > maxTargets {
		b.WriteString(fmt.Sprintf("... %d additional endpoints omitted.\n", len(targets)-maxTargets))
	}

	if len(reps) > 0 {
		b.WriteString("Representative evidence:\n")
		for _, line := range reps {
			b.WriteString(line + "\n")
		}
	}
	for _, note := range policyNotes {
		b.WriteString(note + "\n")
	}
	return strings.TrimSpace(b.String())
}

func buildConciseHighSeverityClusterDetail(group []core.Finding, typeList []string) string {
	targets := uniqueTargetList(group)
	reps := representativeProofLines(group, 3)
	params := collectAffectedParameters(group)
	policyNotes := collectPolicyNotes(group)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Root-cause cluster confirmed via %d vectors/payloads.\n", len(group)))
	if len(typeList) > 0 {
		b.WriteString(fmt.Sprintf("Affected signatures: %s\n", strings.Join(typeList, ", ")))
	}
	b.WriteString(fmt.Sprintf("Affected endpoints: %d\n", len(targets)))
	if len(params) > 0 {
		b.WriteString(fmt.Sprintf("Affected parameters: %s\n", strings.Join(params, ", ")))
	}

	maxTargets := len(targets)
	if maxTargets > 10 {
		maxTargets = 10
	}
	for i := 0; i < maxTargets; i++ {
		b.WriteString(fmt.Sprintf("- %s\n", targets[i]))
	}
	if len(targets) > maxTargets {
		b.WriteString(fmt.Sprintf("... %d additional endpoints omitted.\n", len(targets)-maxTargets))
	}

	if len(reps) > 0 {
		b.WriteString("Representative evidence:\n")
		for _, line := range reps {
			b.WriteString(line + "\n")
		}
	}
	for _, note := range policyNotes {
		b.WriteString(note + "\n")
	}
	return strings.TrimSpace(b.String())
}

func extractMeaningfulProofLine(detail string) string {
	for _, raw := range strings.Split(detail, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "root cause:") ||
			strings.HasPrefix(lower, "impact:") ||
			strings.HasPrefix(lower, "affected parameters:") ||
			strings.HasPrefix(lower, "representative payload evidence") ||
			strings.HasPrefix(lower, "validation status:") ||
			strings.HasPrefix(lower, "evidence quality:") ||
			strings.HasPrefix(lower, "- ") {
			continue
		}
		return scanner.ExecutionProofSignature(line)
	}
	return ""
}

func collectAffectedParameters(group []core.Finding) []string {
	counts := make(map[string]int)
	allSeen := make(map[string]bool)
	groupCount := 0
	for _, g := range group {
		local := make(map[string]bool)
		for _, raw := range strings.Split(g.Detail, "\n") {
			line := strings.TrimSpace(raw)
			if !strings.HasPrefix(strings.ToLower(line), "affected parameters:") {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			for _, p := range strings.Split(parts[1], ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				local[p] = true
			}
		}
		if len(local) == 0 {
			continue
		}
		groupCount++
		for p := range local {
			counts[p]++
			allSeen[p] = true
		}
	}
	if len(allSeen) == 0 {
		return nil
	}

	minCount := 1
	if groupCount >= 4 {
		minCount = (groupCount + 1) / 2
	}

	params := make([]string, 0, len(allSeen))
	for p, count := range counts {
		if count >= minCount {
			params = append(params, p)
		}
	}
	if len(params) == 0 {
		for p := range allSeen {
			params = append(params, p)
		}
	}

	sort.Strings(params)
	return params
}

func collectPolicyNotes(group []core.Finding) []string {
	noteSet := make(map[string]bool)
	for _, g := range group {
		l := strings.ToLower(g.Detail)
		if strings.Contains(l, "configuration exposure only; no auth bypass or data exposure proof was observed") {
			noteSet["Configuration exposure only; no auth bypass or data exposure proof was observed."] = true
		}
		if strings.Contains(l, "policy misconfiguration signal only; no authenticated action, cookie replay, or csrf-over-websocket proof was observed") {
			noteSet["Policy misconfiguration signal only; no authenticated action, cookie replay, or CSRF-over-WebSocket proof was observed."] = true
		}
		if strings.Contains(l, "informational signal only (no deterministic boolean/count/error proof)") {
			noteSet["Informational signal only (no deterministic boolean/count/error proof)."] = true
		}
	}
	if len(noteSet) == 0 {
		return nil
	}
	notes := make([]string, 0, len(noteSet))
	for note := range noteSet {
		notes = append(notes, note)
	}
	sort.Strings(notes)
	return notes
}

func highSeverityScope(fType, endpoint string) (string, string) {
	ep := cleanEndpoint(endpoint)
	u, err := url.Parse(ep)
	if err != nil || u.Host == "" {
		return "endpoint:" + ep, ep
	}

	host := strings.ToLower(u.Host)
	path := strings.TrimSpace(u.Path)
	if path == "" {
		path = "/"
	}
	firstSeg := "/"
	if trimmed := strings.Trim(path, "/"); trimmed != "" {
		firstSeg = "/" + strings.SplitN(trimmed, "/", 2)[0]
	}

	t := strings.ToLower(strings.TrimSpace(fType))
	hostLevelTypes := []string{
		"xslt injection",
		"xpath injection",
		"server-side template injection",
		"prototype pollution",
		"saml vulnerability",
		"improper trust in http headers",
		"cross-site websocket hijacking",
		"jwt none algorithm",
		"nginx configuration error",
		"critical data leak in path",
		"sensitive data exposure",
		"sensitive config",
		"database dump exposed",
		"secret leak",
		"git exposure",
		"local file inclusion",
		"file read / path traversal",
		"file/secret exposure misconfiguration",
		"php type juggling",
		"server-side template injection",
		"vulnerability",
		"nosql injection",
	}
	for _, marker := range hostLevelTypes {
		if strings.Contains(t, marker) {
			return "host:" + host, fmt.Sprintf("Host-level Root Cause (%s)", host)
		}
	}

	familyTypes := []string{
		"sql injection",
		"ssrf injection",
		"remote code execution",
	}
	for _, marker := range familyTypes {
		if strings.Contains(t, marker) {
			return "family:" + host + firstSeg, fmt.Sprintf("Endpoint Family (%s%s)", host, firstSeg)
		}
	}

	return "endpoint:" + ep, ep
}

func highSeverityClusterType(f core.Finding) string {
	t := strings.ToLower(strings.TrimSpace(f.Type))
	d := strings.ToLower(strings.TrimSpace(f.Detail))
	switch {
	case strings.Contains(t, "nosql injection"):
		return "NoSQL Injection"
	case strings.Contains(t, "oracle sqli") || strings.Contains(t, "sql injection"):
		return "SQL Injection"
	case strings.Contains(t, "server-side template injection"):
		if engine := fingerprintSSTIEngine(d); engine != "" {
			return fmt.Sprintf("Server-Side Template Injection (%s)", engine)
		}
		return "Server-Side Template Injection"
	case strings.Contains(t, "xslt injection"):
		if engine := fingerprintXSLTEngine(d); engine != "" {
			return fmt.Sprintf("XSLT Injection (%s)", engine)
		}
		return "XSLT Injection"
	case strings.Contains(t, "xpath injection"):
		return "XPath Injection"
	case strings.Contains(t, "critical data leak in path") ||
		strings.Contains(t, "sensitive data exposure") ||
		strings.Contains(t, "secret leak") ||
		strings.Contains(t, "database dump exposed") ||
		strings.Contains(t, "sensitive config"):
		return "Sensitive Data Exposure"
	case strings.Contains(t, "local file inclusion") || strings.Contains(t, "nginx configuration error"):
		return "File Read / Path Traversal"
	default:
		return f.Type
	}
}

func countUniqueExploitable(findings []core.Finding) int {
	unique := make(map[string]bool)
	for _, f := range findings {
		f = normalizeReportFinding(f)
		if !isValidatedFinding(f) {
			continue
		}
		class := uniqueExploitableClass(f)
		scopeKey, _ := highSeverityScope(class, cleanEndpoint(f.Target))
		unique[class+"|"+scopeKey] = true
	}
	return len(unique)
}

func uniqueExploitableClass(f core.Finding) string {
	clusterType := highSeverityClusterType(f)
	t := strings.ToLower(clusterType)
	switch {
	case strings.Contains(t, "sensitive data exposure"),
		strings.Contains(t, "file read / path traversal"),
		strings.Contains(t, "local file inclusion"):
		return "File/Secret Exposure Misconfiguration"
	default:
		return clusterType
	}
}

func fingerprintSSTIEngine(detailLower string) string {
	switch {
	case strings.Contains(detailLower, "jinja") || strings.Contains(detailLower, "twig"):
		return "Jinja2/Twig"
	case strings.Contains(detailLower, "smarty"):
		return "Smarty"
	case strings.Contains(detailLower, "freemarker"):
		return "Freemarker"
	case strings.Contains(detailLower, "erb") || strings.Contains(detailLower, "ruby"):
		return "Ruby ERB"
	case strings.Contains(detailLower, "mako"):
		return "Mako"
	case strings.Contains(detailLower, "velocity"):
		return "Velocity"
	default:
		return ""
	}
}

func fingerprintXSLTEngine(detailLower string) string {
	switch {
	case strings.Contains(detailLower, "libxslt"):
		return "libxslt"
	case strings.Contains(detailLower, "saxon"):
		return "saxon"
	case strings.Contains(detailLower, "xalan"):
		return "xalan"
	case strings.Contains(detailLower, "msxml"):
		return "msxml"
	default:
		return ""
	}
}

func exploitabilityScore(f core.Finding) int {
	base := 10
	switch normalizeSeverityLabel(f.Severity) {
	case "Critical":
		base = 70
	case "High":
		base = 55
	case "Medium":
		base = 35
	case "Low":
		base = 20
	}

	cluster := strings.ToLower(highSeverityClusterType(f))
	fType := strings.ToLower(strings.TrimSpace(f.Type))
	if severityRank(f.Severity) >= severityRank("High") {
		switch {
		case strings.Contains(cluster, "ssrf injection"):
			base = 95
		case strings.Contains(cluster, "sql injection"):
			base = 80
		case strings.Contains(cluster, "remote code execution"):
			base = 88
		case strings.Contains(cluster, "server-side template injection"),
			strings.Contains(cluster, "xslt injection"),
			strings.Contains(cluster, "xpath injection"):
			base = 78
		case strings.Contains(cluster, "prototype pollution"):
			base = 75
		case strings.Contains(cluster, "jwt none algorithm"):
			base = 60
		case strings.Contains(fType, "graphql introspection"):
			base = 40
		case strings.Contains(fType, "source map"), strings.Contains(fType, "sourcemap"):
			base = 20
		}
	}

	switch f.Confidence.Normalized() {
	case core.ConfidenceConfirmed:
		base += 10
	case core.ConfidenceNoisy:
		base -= 20
	}
	if quality, ok := scanner.ExtractEvidenceQualityScore(f.Detail); ok {
		base = (base + quality) / 2
	}

	if base < 0 {
		return 0
	}
	if base > 100 {
		return 100
	}
	return base
}

func maxSeverityInGroup(group []core.Finding) string {
	maxRank := -1
	maxSeverity := "Info"
	for _, f := range group {
		r := severityRank(f.Severity)
		if r > maxRank {
			maxRank = r
			maxSeverity = normalizeSeverityLabel(f.Severity)
		}
	}
	return maxSeverity
}

func bestConfidenceInGroup(group []core.Finding) core.FindingConfidence {
	best := core.ConfidenceNoisy
	bestRank := core.ConfidenceRank(best)
	for _, f := range group {
		c := f.Confidence.Normalized()
		r := core.ConfidenceRank(c)
		if r > bestRank {
			bestRank = r
			best = c
		}
	}
	return best
}

func severityRank(sev string) int {
	switch normalizeSeverityLabel(sev) {
	case "Critical":
		return 5
	case "High":
		return 4
	case "Medium":
		return 3
	case "Low":
		return 2
	default:
		return 1
	}
}

func normalizeSeverityLabel(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Info"
	}
}
