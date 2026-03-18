package scanner

import (
	"net"
	"net/url"
	"strings"
)

const (
	RuntimeModePublic   = "public"
	RuntimeModeExtended = "extended"
	RuntimeModeResearch = "research"
)

const (
	pluginDirectories  = "directories"
	pluginGit          = "git"
	pluginGraphQL      = "graphql"
	pluginJSAnalyzer   = "jsanalyzer"
	pluginJWT          = "jwt"
	pluginNoSQLi       = "nosqli"
	pluginORMLeak      = "ormleak"
	pluginOpenRedirect = "openredirect"
	pluginPP           = "prototype_pollution"
	pluginProxy        = "proxy"
	pluginRCE          = "rce"
	pluginReconHTML    = "recon_html"
	pluginS3           = "public_storage"
	pluginSAML         = "saml"
	pluginSecrets      = "secrets"
	pluginSQLi         = "sqli"
	pluginSSRF         = "ssrf"
	pluginSSTI         = "ssti"
	pluginTypeJuggle   = "typejuggling"
	pluginVulns        = "vulns_bundle"
	pluginWCD          = "wcd"
	pluginWebSocket    = "websocket"
	pluginXPath        = "xpath"
	pluginXSLT         = "xslt"
	pluginIDOR         = "idor"
)

type pluginPlan map[string]bool

func (p pluginPlan) Enabled(name string) bool {
	return p[name]
}

func endpointExecutionPlugins(plan pluginPlan, rawURL string, isRoot, fast bool) pluginPlan {
	exec := pluginPlan{}
	hasParams := strings.Contains(rawURL, "?")
	lowerURL := strings.ToLower(rawURL)

	if plan.Enabled(pluginSecrets) {
		exec[pluginSecrets] = true
	}

	if !fast && (isRoot || hasParams) {
		if plan.Enabled(pluginVulns) {
			exec[pluginVulns] = true
		} else if plan.Enabled(pluginOpenRedirect) {
			exec[pluginOpenRedirect] = true
		}
		for _, plugin := range []string{
			pluginRCE,
			pluginNoSQLi,
			pluginSQLi,
			pluginSSRF,
			pluginSSTI,
			pluginIDOR,
			pluginXPath,
			pluginXSLT,
			pluginPP,
		} {
			if plan.Enabled(plugin) {
				exec[plugin] = true
			}
		}
	}

	if !fast && (isRoot || strings.Contains(lowerURL, "login") || strings.Contains(lowerURL, "auth")) {
		if plan.Enabled(pluginWCD) {
			exec[pluginWCD] = true
		}
		if plan.Enabled(pluginTypeJuggle) {
			exec[pluginTypeJuggle] = true
		}
	}

	if !fast && plan.Enabled(pluginProxy) {
		exec[pluginProxy] = true
	}

	if isRoot {
		for _, plugin := range []string{pluginGraphQL, pluginGit, pluginS3} {
			if plan.Enabled(plugin) {
				exec[plugin] = true
			}
		}
		if !fast && plan.Enabled(pluginSAML) {
			exec[pluginSAML] = true
		}
	}

	return exec
}

func topLevelExecutionPlugins(plan pluginPlan, hasMainBody, fast bool) pluginPlan {
	exec := pluginPlan{}
	for _, plugin := range []string{pluginDirectories} {
		if plan.Enabled(plugin) {
			exec[plugin] = true
		}
	}

	if !fast {
		for _, plugin := range []string{pluginWebSocket, pluginORMLeak} {
			if plan.Enabled(plugin) {
				exec[plugin] = true
			}
		}
	}

	if hasMainBody {
		if plan.Enabled(pluginReconHTML) {
			exec[pluginReconHTML] = true
		}
		if plan.Enabled(pluginJSAnalyzer) {
			exec[pluginJSAnalyzer] = true
		}
		if !fast && plan.Enabled(pluginJWT) {
			exec[pluginJWT] = true
		}
	}

	return exec
}

// NormalizeRuntimeMode canonicalizes CLI/runtime modes for plugin selection and report metadata.
func NormalizeRuntimeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "public", "strict", "bounty":
		return RuntimeModePublic
	case "extended", "balanced":
		return RuntimeModeExtended
	case "research", "aggressive", "lab":
		return RuntimeModeResearch
	default:
		return RuntimeModePublic
	}
}

func normalizeEvidenceMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "public":
		return "balanced"
	case "extended":
		return "balanced"
	case "research":
		return "aggressive"
	case "bounty", "strict":
		return "strict"
	case "lab", "aggressive":
		return "aggressive"
	default:
		return "balanced"
	}
}

func planForRuntimeMode(mode string) pluginPlan {
	plan := pluginPlan{
		pluginDirectories: true,
		pluginGit:         true,
		pluginGraphQL:     true,
		pluginJSAnalyzer:  true,
		pluginReconHTML:   true,
		pluginS3:          true,
		pluginSecrets:     true,
	}

	switch NormalizeRuntimeMode(mode) {
	case RuntimeModeExtended:
		plan[pluginOpenRedirect] = true
		plan[pluginORMLeak] = true
		plan[pluginProxy] = true
		plan[pluginWebSocket] = true
	case RuntimeModeResearch:
		plan[pluginOpenRedirect] = true
		plan[pluginORMLeak] = true
		plan[pluginProxy] = true
		plan[pluginWebSocket] = true
		plan[pluginJWT] = true
		plan[pluginNoSQLi] = true
		plan[pluginPP] = true
		plan[pluginRCE] = true
		plan[pluginSAML] = true
		plan[pluginSQLi] = true
		plan[pluginSSRF] = true
		plan[pluginSSTI] = true
		plan[pluginTypeJuggle] = true
		plan[pluginVulns] = true
		plan[pluginWCD] = true
		plan[pluginWebSocket] = true
		plan[pluginXPath] = true
		plan[pluginXSLT] = true
		plan[pluginIDOR] = true
	}

	return plan
}

func targetDomainForPublicStorage(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}

	if parsed, err := url.Parse(target); err == nil {
		host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
		if host != "" && net.ParseIP(host) == nil {
			return host
		}
	}

	candidate := strings.ToLower(target)
	if idx := strings.Index(candidate, "/"); idx != -1 {
		candidate = candidate[:idx]
	}
	if idx := strings.Index(candidate, ":"); idx != -1 {
		candidate = candidate[:idx]
	}
	if candidate == "" || net.ParseIP(candidate) != nil {
		return ""
	}
	return candidate
}
