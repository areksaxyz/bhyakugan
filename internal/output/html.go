package output

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yupiyy/bhyakugan/internal/core"
)

func cleanEndpoint(urlStr string) string {
	if idx := strings.Index(urlStr, "?"); idx != -1 {
		return urlStr[:idx]
	}
	return urlStr
}

func GenerateHTML(filename string, rawFindings []core.Finding, liveHosts []string, target string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// Impact per Endpoint (Priority 4 - Refactored: Canonical & Conflict Resolution)
	endpointImpacts := make(map[string]map[string]bool)
	endpointTypes := make(map[string]string) // Track detected backend type (SQL vs NoSQL)

	for _, f := range rawFindings {
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
	findings := consolidateFindings(rawFindings)

	// Group findings by Severity
	grouped := make(map[string][]core.Finding)
	stats := make(map[string]int)

	// Initialize with 0
	severities := []string{"Critical", "High", "Medium", "Low", "Info"}
	for _, sev := range severities {
		stats[sev] = 0
		grouped[sev] = []core.Finding{}
	}

	for _, fnd := range findings {
		if _, ok := grouped[fnd.Severity]; !ok {
			grouped["Info"] = append(grouped["Info"], fnd)
			stats["Info"]++
		} else {
			grouped[fnd.Severity] = append(grouped[fnd.Severity], fnd)
			stats[fnd.Severity]++
		}
	}

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
        
        .card.critical::before { background: var(--critical); } .card.critical h3 { color: var(--critical); }
        .card.high::before { background: var(--high); } .card.high h3 { color: var(--high); }
        .card.medium::before { background: var(--medium); } .card.medium h3 { color: var(--medium); }
        .card.low::before { background: var(--low); } .card.low h3 { color: var(--low); }
        .card.info::before { background: var(--info); } .card.info h3 { color: var(--info); }

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
        
        .col-type { width: 20%%; font-weight: 700; color: var(--primary); }
        .col-target { width: 35%%; word-break: break-all; }
        .col-detail { width: 45%%; color: var(--text-muted); font-size: 0.85rem; line-height: 1.6; white-space: pre-wrap; }
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
                <p style="margin: 8px 0 0 0; color: var(--text-muted); font-weight: 500;">Security Assessment Outcome</p>
            </div>
            <div class="header-meta">
                <p>Target: <a href="%s" target="_blank">%s</a></p>
                <p>Date: <strong>%s</strong></p>
                <p>Live Hosts: <strong>%d</strong></p>
            </div>
        </div>

        <div class="dashboard">
            <div class="card critical"><h3>%d</h3><p>Critical</p></div>
            <div class="card high"><h3>%d</h3><p>High</p></div>
            <div class="card medium"><h3>%d</h3><p>Medium</p></div>
            <div class="card low"><h3>%d</h3><p>Low</p></div>
            <div class="card info"><h3>%d</h3><p>Info</p></div>
        </div>
`, target, target, target, time.Now().Format("Jan 02, 2006 15:04:05 MST"), len(liveHosts), stats["Critical"], stats["High"], stats["Medium"], stats["Low"], stats["Info"])

	if _, err := f.WriteString(htmlHead); err != nil {
		return err
	}

	// Render Impact Summary
	if len(endpointImpacts) > 0 {
		f.WriteString(`<div class="impact-summary"><h2>Confirmed Impacts by Endpoint:</h2>`)
		for endpoint, imps := range endpointImpacts {
			f.WriteString(fmt.Sprintf(`<div class="impact-group"><h3>%s</h3><div class="impact-list">`, endpoint))
			for imp := range imps {
				f.WriteString(fmt.Sprintf(`<div class="impact-item">%s</div>`, imp))
			}
			f.WriteString(`</div></div>`)
		}
		f.WriteString(`</div>`)
	}

	// Render Tables by Severity
	for _, sev := range severities {
		items := grouped[sev]
		if len(items) == 0 {
			continue
		}

		sectionHeader := fmt.Sprintf(`
        <div class="section-title">
            <span class="section-badge bg-%s">%s</span> Findings (%d)
        </div>
        <div class="table-container">
            <table>
                <thead><tr><th class="col-type">Vulnerability Type</th><th class="col-target">Target Endpoint</th><th>Confidence</th><th class="col-detail">Evidence / Details</th></tr></thead>
                <tbody>`, sev, sev, len(items))

		if _, err := f.WriteString(sectionHeader); err != nil {
			return err
		}

		for _, fnd := range items {
			// Display Clean Endpoint in Table, Full URL in Link
			displayTarget := cleanEndpoint(fnd.Target)
			if fnd.Type == "SAML Endpoints Detected" || strings.Contains(fnd.Target, "Endpoints Detected") {
				displayTarget = fnd.Target // Keep "90 Endpoints" label
			}

			targetCell := displayTarget
			targetLower := strings.ToLower(strings.TrimSpace(fnd.Target))
			if strings.HasPrefix(targetLower, "http://") || strings.HasPrefix(targetLower, "https://") {
				targetCell = fmt.Sprintf(`<a href="%s" target="_blank">%s</a>`, fnd.Target, displayTarget)
			}

			row := fmt.Sprintf(`
            <tr>
                <td class="col-type">%s</td>
                <td class="col-target">%s</td>
                <td>%s</td>
                <td class="col-detail">%s</td>
            </tr>`, fnd.Type, targetCell, strings.ToUpper(defaultConfidence(fnd.Confidence)), fnd.Detail)
			if _, err := f.WriteString(row); err != nil {
				return err
			}
		}

		if _, err := f.WriteString("</tbody></table></div>"); err != nil {
			return err
		}
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
	f, err := os.Create(filename)
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

func defaultConfidence(c string) string {
	c = strings.TrimSpace(strings.ToLower(c))
	if c == "" {
		return "probable"
	}
	return c
}

func consolidateFindings(findings []core.Finding) []core.Finding {
	var consolidated []core.Finding

	// Map to group findings
	// Key format varies by severity to support different consolidation strategies
	grouped := make(map[string][]core.Finding)

	for _, f := range findings {
		// --- LABEL REFINEMENT ---
		fType := f.Type
		if fType == "Hidden Directory" || fType == "Protected Directory" {
			fType = "Accessible Path"
		}

		var key string
		if f.Severity == "Critical" || f.Severity == "High" {
			// Strategy: Per-Endpoint Consolidation for High Impact
			// We want to group multiple vectors (e.g. NoSQL $ne, $gt) on the SAME endpoint into one finding.
			// Key: Type | Severity | Endpoint
			ep := cleanEndpoint(f.Target)
			key = fmt.Sprintf("%s|%s|%s", fType, f.Severity, ep)
		} else {
			// Strategy: Global Consolidation for Noise Reduction
			// We want to group widespread low-impact issues (e.g. Missing Headers on 50 pages).
			// Key: Type | Severity
			key = fmt.Sprintf("%s|%s", fType, f.Severity)
		}

		grouped[key] = append(grouped[key], f)
	}

	for key, group := range grouped {
		parts := strings.Split(key, "|")
		fType := parts[0]
		fSeverity := parts[1]

		// --- HANDLING CRITICAL / HIGH ---
		if fSeverity == "Critical" || fSeverity == "High" {
			if len(group) > 1 {
				// Consolidate multiple vectors on the same endpoint
				ep := cleanEndpoint(group[0].Target)

				var detailsBuilder strings.Builder
				detailsBuilder.WriteString(fmt.Sprintf("Vulnerability confirmed via %d vectors/payloads on this endpoint.\n\nVectors:\n", len(group)))

				for i, f := range group {
					// Clean up detail for list format
					cleanDetail := strings.ReplaceAll(f.Detail, "\n", "\n   ") // Indent multi-line details
					detailsBuilder.WriteString(fmt.Sprintf("%d. %s\n   [Ref: %s]\n\n", i+1, cleanDetail, f.Target))
				}

				consolidated = append(consolidated, core.Finding{
					Type:     fType,
					Target:   ep, // Use the clean endpoint as the main target
					Detail:   detailsBuilder.String(),
					Severity: fSeverity,
				})
			} else {
				// Single finding, add as is
				consolidated = append(consolidated, group...)
			}
			continue
		}

		// --- HANDLING MEDIUM / LOW / INFO ---

		shouldConsolidate := len(group) > 1 && (strings.Contains(fType, "Web Cache") ||
			strings.Contains(fType, "ORM Leak") ||
			strings.Contains(fType, "S3 Bucket") ||
			strings.Contains(fType, "SQL Injection") ||
			strings.Contains(fType, "GraphQL") ||
			strings.Contains(fType, "SAML") ||
			fType == "Accessible Path" ||
			fType == "Mobile-Specific Endpoint")

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

			// Special handling for GraphQL Info
			if strings.Contains(fType, "GraphQL") {
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
				Type:     fType,
				Target:   fmt.Sprintf("%d Endpoints Detected", len(group)),
				Detail:   detailsBuilder.String(),
				Severity: fSeverity,
			})
		} else {
			consolidated = append(consolidated, group...)
		}
	}

	return consolidated
}
