package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type routeContent struct {
	status      int
	contentType string
	body        string
}

var (
	internalHeaderKeys = []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"True-Client-IP",
		"Client-IP",
		"Forwarded",
		"X-Originating-IP",
		"X-Remote-IP",
		"X-Remote-Addr",
		"X-Client-IP",
		"X-Host",
		"X-Forwarded-Host",
		"X-Forwarded-Server",
	}

	sensitiveRoutes = map[string]routeContent{
		"/.env": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "APP_ENV=production\nAPP_KEY=base64:LOCALHOST_LAB_KEY_123456789\nDB_HOST=127.0.0.1\nDB_DATABASE=prod\nDB_USERNAME=bhyakugan\nDB_PASSWORD=ultra-secret\n",
		},
		"/.env.old": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "APP_KEY=base64:OLD_LOCALHOST_KEY\nDB_PASSWORD=old-secret\n",
		},
		"/.env.bak": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "APP_KEY=base64:BAK_LOCALHOST_KEY\nDB_PASSWORD=backup-secret\n",
		},
		"/.env.php": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "<?php\nreturn ['password' => 'db-super-secret'];\n",
		},
		"/.git/HEAD": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "ref: refs/heads/main\n",
		},
		"/.git/config": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "[remote \"origin\"]\n\turl = git@github.com:target/private-monolith.git\n",
		},
		"/server-status": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "Apache Status\nScoreboard: _W___K___\n",
		},
		"/web.config": {
			status:      200,
			contentType: "application/xml",
			body:        "<configuration><system.webServer><rewrite><rules></rules></rewrite></system.webServer></configuration>",
		},
		"/.htaccess": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "RewriteEngine On\nRewriteRule ^(.*)$ index.php [L]\nOptions -Indexes\n",
		},
		"/db.sql": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "-- MySQL dump\nCREATE TABLE users(id INT, email VARCHAR(255));\nINSERT INTO users VALUES (1,'admin@corp.local');\nINSERT INTO donatur VALUES (1,'Alice');\n",
		},
		"/database.sql": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "CREATE TABLE accounts(id INT, role VARCHAR(32));\nINSERT INTO admin_accounts VALUES (1,'root');\n",
		},
		"/backup.sql": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "-- MYSQLDUMP\nCREATE TABLE customer(id INT, name VARCHAR(128));\nINSERT INTO customer VALUES (7,'John');\n",
		},
		"/.ssh/id_rsa": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDQi9Ki7Y7Lk2wb
U8adf6jQYh6h3m7D8vP7K8x3NVBh9Wm9b8aY0abV3fMz7R9v4vD4VJ1J8cHkN42x
9+ByP8r7c0L8h4yV0A5wM3X1j9u4J8M7Q2eT1M9i6s6n1n4yV8D1q2r7s1f7a1j8
0Q7fY2zN9V1m0H4p8K6m9Q3u3A2H5mM1X2n4m2k9p8q7r4s2c9v8y2b5a1z6t8p3
-----END PRIVATE KEY-----`,
		},
		"/storage/logs/laravel.log": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "[error] stack trace: SQLSTATE[HY000] Access denied",
		},
		"/wp-content/debug.log": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "PHP Notice: Undefined variable in /var/www/html/wp-config.php",
		},
		"/.aws/credentials": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "[default]\naws_access_key_id=AKIA1234567890ABCD\naws_secret_access_key=super-secret-access\n",
		},
		"/config/database.php": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "<?php\nreturn ['password' => 's3cur3-db-pass'];\n",
		},
		"/package.json": {
			status:      200,
			contentType: "application/json",
			body:        `{ "name": "advanced-lab", "dependencies": {"express": "^4.18.2"} }`,
		},
		"/package-lock.json": {
			status:      200,
			contentType: "application/json",
			body:        `{ "name": "advanced-lab", "lockfileVersion": 3 }`,
		},
		"/Dockerfile": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "FROM golang:1.22\nWORKDIR /app\n",
		},
		"/google-keys": {
			status:      200,
			contentType: "text/html; charset=utf-8",
			body:        `<html><body><h1>Google API Keys</h1><p>Vulnerable: AIzaVulnerableKey12345678901234567890</p><p>Restricted: AIzaRestrictedKey09876543210987654321</p></body></html>`,
		},
		"/docker-compose.yml": {
			status:      200,
			contentType: "text/plain; charset=utf-8",
			body:        "services:\n  app:\n    image: advanced-lab\n",
		},
	}
)

func main() {
	rand.Seed(time.Now().UnixNano())

	port := os.Getenv("MOCKSERVER_PORT")
	if port == "" {
		port = "8084"
	}

	mux := http.NewServeMux()

	// GraphQL paths
	for _, p := range []string{"/graphql", "/api/graphql", "/v1/graphql", "/graphql/console", "/explorer", "/v1/graphiql", "/graphiql"} {
		mux.HandleFunc(p, handleGraphQL)
	}

	// SAML paths
	for _, p := range []string{"/saml/acs", "/saml2/acs", "/SAML2/POST", "/auth/saml/callback", "/saml/consume"} {
		mux.HandleFunc(p, handleSAML)
	}

	// WebSocket paths
	for _, p := range []string{"/ws", "/websocket", "/socket.io/", "/chat", "/realtime", "/api/v1/ws", "/cable"} {
		mux.HandleFunc(p, handleWebSocket)
	}

	mux.HandleFunc("/redirect", handleOpenRedirect)
	mux.HandleFunc("/maps/api/geocode/json", handleGoogleMock)
	mux.HandleFunc("/v1/images:annotate", handleGoogleMock)
	mux.HandleFunc("/v1beta/models", handleGoogleMock)
	mux.HandleFunc("/v1/projects/x/installations", handleGoogleMock)

	// Application routes
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/auth/login", handleAuthLogin)
	mux.HandleFunc("/template", handleTemplate)
	mux.HandleFunc("/api/fetch", handleFetch)
	mux.HandleFunc("/api/upload", handleFileUpload)
	mux.HandleFunc("/api/login", handleAPILogin)
	mux.HandleFunc("/vuln/eval", handleEval)
	mux.HandleFunc("/vuln/sql", handleSQL)
	mux.HandleFunc("/vuln/oracle", handleOracle)
	mux.HandleFunc("/vuln/xpath", handleXPathDemo)
	mux.HandleFunc("/vuln/xslt", handleXSLTDemo)
	mux.HandleFunc("/static/app.js", handleAppJS)
	mux.HandleFunc("/static/app.js.map", handleAppJSMap)
	mux.HandleFunc("/static/theme.css", handleThemeCSS)
	mux.HandleFunc("/api/public/catalog", handleCatalog)
	mux.HandleFunc("/static/config.js", handleDynamicJS)
	mux.HandleFunc("/static/auth-utils.js", handleAuthUtilsJS)
	mux.HandleFunc("/deleteCompanyModules", handleSQLiVulnerable)
	mux.HandleFunc("/trap/reflection", handleTrapReflection)
	mux.HandleFunc("/trap/soft404", handleTrapSoft404)
	mux.HandleFunc("/trap/sql-static", handleTrapSQLStatic)

	fmt.Printf("[+] Bhyakugan Localhost Lab running on http://127.0.0.1:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func handleDynamicJS(w http.ResponseWriter, r *http.Request) {
	// Simulate content change based on cookie (XSSI)
	cookie, err := r.Cookie("PHPSESSID")
	js := `var config = { "api": "/api/v1", "version": "1.0.0" };`
	if err == nil && cookie.Value != "" {
		js = `var config = { "api": "/api/v1", "version": "1.0.0", "csrf": "csrf-dynamic-token-12345", "session": "` + cookie.Value + `" };`
	}
	w.Header().Set("Content-Type", "application/javascript")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(js))
}

func handleAuthUtilsJS(w http.ResponseWriter, r *http.Request) {
	js := `
var tokenConstant = "IUNvbXBhbnlAMSE=";
function getSDToken(deviceId, userId, strDesc) {
    var dateConstant = Math.floor(new Date().getTime()/21600000);
    var sdTokenTemp = deviceId + "|" + userId + "|" + strDesc + "|" + dateConstant;
    var encoded = CryptoJS.HmacSHA256(sdTokenTemp, tokenConstant);
    return encoded.toString(CryptoJS.enc.Base64);
}
`
	w.Header().Set("Content-Type", "application/javascript")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(js))
}

func handleSQLiVulnerable(w http.ResponseWriter, r *http.Request) {
	companyID := r.URL.Query().Get("companyID")
	if strings.Contains(companyID, "'") {
		writeText(w, 500, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1")
		return
	}
	writeJSON(w, 200, `{"status":"success","message":"Modules deleted"}`)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		handleRootPOST(w, r)
		return
	}

	if served := maybeServeSensitiveFile(w, r); served {
		return
	}

	if served := maybeServeLFIOrWrapper(w, r); served {
		return
	}

	if alg := jwtAlgFromHeader(r.Header.Get("Authorization")); strings.EqualFold(alg, "none") {
		writeJSON(w, 200, `{"authenticated":true,"role":"admin","success":true,"dashboard":"root"}`)
		return
	}

	if served := maybeServeXPathOrXSLT(w, r); served {
		return
	}

	if isNoSQLPayload(r) {
		writeJSON(w, 200, `{"success":true,"auth":true,"message":"welcome admin","dashboard":"/admin"}`)
		return
	}

	if isWCDPath(r) {
		w.Header().Set("X-Cache", "HIT")
		w.Header().Set("Set-Cookie", "sessionid=wcd-hit-token; Path=/")
		writeHTML(w, 200, baseDashboardHTML(true))
		return
	}

	if isProxyInternalPath(r.URL.Path) {
		handleInternalProtected(w, r)
		return
	}

	switch r.URL.Path {
	case "/static../.env", "/assets../.env", "/js../.env", "/css../.env":
		writeText(w, 200, "APP_ENV=prod\nDB_PASSWORD=proxy-bypass\nSECRET=nginx-alias\n")
		return
	}

	if strings.Contains(r.URL.RawQuery, "user__startswith=adm") || strings.Contains(r.URL.RawQuery, "user__regex=%5Eadm") {
		writeHTML(w, 200, `<html><body><h1>Django Admin</h1><p>admin success profile loaded</p><pre>HASH(user)=9af31</pre></body></html>`)
		return
	}
	if strings.Contains(r.URL.RawQuery, "user__contains=dmi") {
		writeHTML(w, 200, `<html><body><p>admin success data visible</p><pre>Array(user,role)</pre></body></html>`)
		return
	}

	w.Header().Add("Set-Cookie", "PHPSESSID=php-session-live; Path=/")
	w.Header().Add("Set-Cookie", "csrftoken=django-csrf-live; Path=/")
	w.Header().Add("Set-Cookie", "sessionid=django-session-live; Path=/")
	writeHTML(w, 200, baseDashboardHTML(false))
}

func handleRootPOST(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	bodyStr := strings.ToLower(string(body))

	if strings.Contains(bodyStr, "__proto__") || strings.Contains(bodyStr, "constructor") {
		switch {
		case strings.Contains(bodyStr, `"json spaces"`) && strings.Contains(bodyStr, "10"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("{\"result\":          \"ok\"}"))
			return
		case strings.Contains(bodyStr, `"status":510`) || strings.Contains(bodyStr, `"status": 510`):
			writeJSON(w, 510, `{"error":"prototype-overwrite"}`)
			return
		case strings.Contains(bodyStr, `"isadmin": true`) || strings.Contains(bodyStr, `"admin": true`):
			writeJSON(w, 200, `{"welcome":"admin panel","state":"escalated"}`)
			return
		case strings.Contains(bodyStr, `"authenticated": true`) || strings.Contains(bodyStr, `"auth": true`):
			writeJSON(w, 200, `{"success":true,"auth":true}`)
			return
		default:
			writeJSON(w, 200, `{"success":false}`)
			return
		}
	}

	if isNoSQLBody(bodyStr) {
		writeJSON(w, 200, `{"success":true,"auth":true,"dashboard":"/admin"}`)
		return
	}

	writeJSON(w, 200, `{"ok":true}`)
}

func handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if served := maybeServeXPathOrXSLT(w, r); served {
		return
	}

	q := r.URL.Query()
	if q.Get("bhyakugan_control") == "true" || strings.Contains(strings.ToLower(r.URL.RawQuery), "bhyakugan_control=true") {
		writeHTML(w, 200, `<html><body><h1>Login</h1><p>Please sign in.</p></body></html>`)
		return
	}

	// PHP type juggling bypass simulation
	if strings.Contains(r.URL.RawQuery, "pass%5B%5D=") || strings.Contains(strings.ToUpper(r.URL.RawQuery), "QNKCDZO") || hasArrayParam(q) {
		writeHTML(w, 200, `<html><body><h1>Dashboard</h1><p>welcome, administrator</p><a href="/logout">logout</a><pre>session_id=local-12345</pre><div>profile settings</div><section>trusted console trusted console trusted console trusted console trusted console trusted console trusted console trusted console trusted console trusted console</section></body></html>`)
		return
	}

	if isNoSQLPayload(r) || (q.Get("user") == "admin" && q.Get("pass") == "admin") {
		writeJSON(w, 200, `{"success":true,"auth":true,"dashboard":"/auth/me"}`)
		return
	}

	writeHTML(w, 401, `<html><body><h1>Unauthorized</h1><p>invalid credentials</p></body></html>`)
}

func handleTemplate(w http.ResponseWriter, r *http.Request) {
	if served := maybeServeXPathOrXSLT(w, r); served {
		return
	}

	q := r.URL.Query()
	input := q.Get("q")
	if input == "" {
		input = q.Get("template")
	}
	clean := strings.ReplaceAll(strings.ToLower(input), " ", "")
	if strings.Contains(clean, "13377331*2") {
		writeText(w, 200, "Rendered Result: 26754662")
		return
	}

	writeHTML(w, 200, `<html><body><h1>Template Preview</h1><div>Status: draft</div></body></html>`)
}

func handleFetch(w http.ResponseWriter, r *http.Request) {
	if served := maybeServeXPathOrXSLT(w, r); served {
		return
	}

	target := firstNonEmpty(
		r.URL.Query().Get("url"),
		r.URL.Query().Get("u"),
		r.URL.Query().Get("next"),
		r.URL.Query().Get("redirect"),
		r.URL.Query().Get("dest"),
		r.URL.Query().Get("uri"),
	)
	targetLower := strings.ToLower(target)

	switch {
	case strings.Contains(targetLower, "169.254.169.254/latest/meta-data"):
		writeJSON(w, 200, `{"ami-id":"ami-localhost-lab","instance-id":"i-local-12345","local-ipv4":"10.10.0.24","hostname":"lab-aws-host","security-credentials":"bhyakugan-role"}`)
	case strings.Contains(targetLower, "metadata/instance"):
		writeJSON(w, 200, `{"compute":{"name":"vm-lab","vmId":"azure-vm-7001","subscriptionId":"sub-local-001","resourceGroupName":"rg-lab","osProfile":{"computerName":"vm-lab"}}}`)
	case strings.Contains(targetLower, "metadata/v1.json"):
		writeJSON(w, 200, `{"droplet_id":7001,"hostname":"do-lab-01","region":"sgp1","interfaces":{"public":[{"ipv4":{"ip_address":"134.209.1.11"}}]}}`)
	case strings.Contains(targetLower, "192.0.0.192/1.0/meta-data"):
		writeJSON(w, 200, `{"instance-id":"ocid1.instance.oc1.ap-singapore-1.local","availability-domain":"SIN-AD-1","compartment-id":"ocid1.compartment.oc1..local","canonical-region-name":"ap-singapore-1","shape":"VM.Standard.E4.Flex","region":"ap-singapore-1"}`)
	case strings.Contains(targetLower, "2852039166") || strings.Contains(targetLower, "nip.io"):
		writeJSON(w, 200, `{"ami-id":"ami-bypass-encoded","instance-id":"i-bypass-9001","local-ipv4":"10.20.30.40"}`)
	case strings.Contains(targetLower, "127.0.0.1") || strings.Contains(targetLower, "0x7f000001") || strings.Contains(targetLower, "127.127.127.127") || strings.Contains(targetLower, "file:///etc/passwd") || strings.Contains(targetLower, "gopher://"):
		writeText(w, 200, "root:x:0:0:root:/root:/bin/bash")
	default:
		writeJSON(w, 200, `{"status":"fetched","preview":"public content"}`)
	}
}

func handleAPILogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		body, _ := io.ReadAll(r.Body)
		if isNoSQLBody(strings.ToLower(string(body))) {
			writeJSON(w, 200, `{"success":true,"auth":true,"dashboard":"/admin"}`)
			return
		}
	}
	if isNoSQLPayload(r) {
		writeJSON(w, 200, `{"success":true,"auth":true,"dashboard":"/admin"}`)
		return
	}
	writeJSON(w, 401, `{"success":false,"error":"invalid credentials"}`)
}

func handleEval(w http.ResponseWriter, r *http.Request) {
	if served := maybeServeXPathOrXSLT(w, r); served {
		return
	}

	cmd := firstNonEmpty(
		r.URL.Query().Get("cmd"),
		r.URL.Query().Get("exec"),
		r.URL.Query().Get("code"),
		r.URL.Query().Get("eval"),
		r.URL.Query().Get("query"),
		r.URL.Query().Get("q"),
	)
	cmdLower := strings.ToLower(cmd)

	if strings.Contains(cmdLower, "sleep") {
		time.Sleep(7 * time.Second)
		writeText(w, 200, "Delayed command executed")
		return
	}
	if strings.Contains(cmdLower, "id") || strings.Contains(cmdLower, "process.mainmodule") {
		writeText(w, 200, "uid=1000(app) gid=1000(app) groups=1000(app)")
		return
	}

	writeText(w, 200, "command endpoint ready")
}

func handleSQL(w http.ResponseWriter, r *http.Request) {
	if served := maybeServeXPathOrXSLT(w, r); served {
		return
	}

	if isNoSQLPayload(r) {
		writeJSON(w, 200, `{"success":true,"auth":true,"dashboard":"/admin"}`)
		return
	}

	value := firstNonEmpty(r.URL.Query().Get("id"), r.URL.Query().Get("user"), r.URL.Query().Get("search"))
	low := strings.ToLower(value)

	if strings.Contains(low, "sleep(5)") || strings.Contains(low, "pg_sleep(5)") || strings.Contains(low, "benchmark(") {
		time.Sleep(6 * time.Second)
		writeText(w, 200, "slow query result")
		return
	}
	if strings.Contains(low, "'") || strings.Contains(low, "extractvalue") || strings.Contains(low, "convert(int") || strings.Contains(low, "cast(version") {
		writeText(w, 500, "You have an error in your SQL syntax near 'payload' at line 1")
		return
	}

	writeHTML(w, 200, `<html><body><h1>Products</h1><p>item list normal</p></body></html>`)
}

func handleOracle(w http.ResponseWriter, r *http.Request) {
	value := firstNonEmpty(r.URL.Query().Get("id"), r.URL.Query().Get("q"))
	low := strings.ToLower(value)

	switch {
	case strings.Contains(low, "case when(1=2)"):
		writeText(w, 500, "ORA-01476: divisor is equal to zero")
	case strings.Contains(low, "case when(1=1)"):
		writeHTML(w, 200, `<html><body><h1>Oracle Account</h1><p>Welcome admin dashboard</p></body></html>`)
	default:
		writeHTML(w, 200, `<html><body><h1>Oracle Account</h1><p>normal account page</p></body></html>`)
	}
}

func handleXPathDemo(w http.ResponseWriter, r *http.Request) {
	if served := maybeServeXPathOrXSLT(w, r); served {
		return
	}
	writeHTML(w, 200, `<html><body><h1>XPath demo page</h1></body></html>`)
}

func handleXSLTDemo(w http.ResponseWriter, r *http.Request) {
	if served := maybeServeXPathOrXSLT(w, r); served {
		return
	}
	writeHTML(w, 200, `<html><body><h1>XSLT demo page</h1></body></html>`)
}

func handleGraphiQL(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, 200, `<!doctype html><html><body><h1>GraphiQL</h1><p>graphql playground ready</p></body></html>`)
}

func handleGraphQL(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, 400, `{"errors":[{"message":"Syntax Error: Unexpected Name"}]}`)
		return
	}

	body, _ := io.ReadAll(r.Body)
	bodyStr := strings.TrimSpace(string(body))
	lower := strings.ToLower(bodyStr)

	if strings.HasPrefix(bodyStr, "[") {
		writeJSON(w, 200, `[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`)
		return
	}
	if strings.Contains(lower, "__schema") || strings.Contains(lower, "introspectionquery") {
		writeJSON(w, 200, `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`)
		return
	}

	if strings.Contains(lower, "policypageassetgroup") {
		writeJSON(w, 200, `{"data":{"node":{"id":"Z2lkOi8vaGFja2Vyb25lL1BvbGljeVBhZ2VBc3NldEdyb3Vwc0luZGV4OjpQb2xpY3lQYWdlQXNzZXRHcm91cC8zOTgxLTQxMjg3","name":"Vulnerable Private Program Scope"}}}`)
		return
	}

	if strings.Contains(lower, "organizations") && strings.Contains(lower, "projects") {
		if strings.Contains(lower, "suggestedcollaborators") {
			writeJSON(w, 200, `{"data":{"organizations":[{"projects":[{"suggestedCollaborators":[{"id":"1","email":"admin@corp.local","role":"ADMIN"},{"id":"2","email":"victim@corp.local","role":"USER"}]}]}]}}`)
			return
		}
		writeJSON(w, 200, `{"data":{"organizations":[{"projects":[{"name":"Secret AI Project","webhooks":[{"id":"99","url":"https://hooks.internal/vulnerable"}]}]}]}}`)
		return
	}

	writeJSON(w, 200, `{"data":{"__typename":"Query"}}`)
}

func handleSAML(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Allow", "POST")
		writeText(w, 405, "SAML AssertionConsumerService endpoint")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeText(w, 400, "invalid form")
		return
	}
	if r.Form.Get("SAMLResponse") == "" {
		writeText(w, 400, "SAMLResponse required")
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(r.Form.Get("SAMLResponse"))
	if err != nil {
		writeText(w, 400, "invalid SAMLResponse encoding")
		return
	}
	decodedLower := strings.ToLower(string(decoded))
	if !strings.Contains(decodedLower, "<saml2p:response") || !strings.Contains(decodedLower, "<saml2:assertion") {
		writeText(w, 400, "invalid SAML payload structure")
		return
	}

	w.Header().Set("Set-Cookie", "auth_token=saml-bypass-ok; Path=/")
	w.Header().Set("Location", "/dashboard")
	w.WriteHeader(302)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	if upgrade == "websocket" {
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.WriteHeader(101)
		return
	}

	w.Header().Set("Upgrade", "websocket")
	writeText(w, 426, "Upgrade Required")
}

func handleAppJS(w http.ResponseWriter, r *http.Request) {
	js := `(() => {
  const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.signature";
  const leakedAws = "AKIA1234567890ABCD";
  const ciConfig = "'password' => 're4lDbPass123'";
  const apiEndpoints = [
    "/api/v1/admin",
    "/api/fetch",
    "/graphql",
    "/admin/metrics",
    "/backup.sql",
    "/config/database.php",
    "/internal/config.json"
  ];

          async function loadCatalog() {
            const resp = await fetch("/api/public/catalog");
            const data = await resp.json();
            const el = document.getElementById("catalog");
            el.innerHTML = data.items.map((x) => "<li><strong>" + x.name + "</strong> - " + x.price + "</li>").join("");
          }

  document.addEventListener("DOMContentLoaded", () => {
    const tokenEl = document.getElementById("jwt-token");
    if (tokenEl) tokenEl.textContent = jwt;
    loadCatalog();
    window.__advancedLab = { apiEndpoints, leakedAws, ciConfig };
  });
})();`

	w.Header().Set("Content-Type", "application/javascript")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(js))
}

func handleAppJSMap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(`{"version":3,"file":"app.js","sources":["webpack://advanced-lab/src/main.ts"],"names":[]}`))
}

func handleThemeCSS(w http.ResponseWriter, r *http.Request) {
	css := `:root {
  --bg: radial-gradient(circle at top right, #0b1220 0%, #121826 38%, #1d2333 100%);
  --card: rgba(24, 31, 47, 0.82);
  --line: #2e3f5d;
  --teal: #16d4b8;
  --orange: #ff8a3d;
  --text: #dce8ff;
  --muted: #8ea4c9;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "Space Grotesk", "Segoe UI", sans-serif;
  color: var(--text);
  background: var(--bg);
  min-height: 100vh;
}
.wrapper { max-width: 1100px; margin: 0 auto; padding: 28px; }
.hero {
  border: 1px solid var(--line);
  border-radius: 18px;
  background: linear-gradient(140deg, rgba(12,22,40,0.96), rgba(19,32,54,0.86));
  box-shadow: 0 24px 58px rgba(2, 7, 21, 0.45);
  padding: 34px;
}
.hero h1 { margin: 0; font-size: clamp(1.8rem, 5vw, 2.8rem); letter-spacing: 0.03em; }
.hero p { color: var(--muted); max-width: 72ch; }
.grid {
  margin-top: 22px;
  display: grid;
  gap: 16px;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
}
.card {
  border: 1px solid #2b3a56;
  border-radius: 14px;
  padding: 16px;
  background: var(--card);
}
.tag {
  display: inline-block;
  font-size: 0.74rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: #071826;
  background: linear-gradient(90deg, var(--teal), var(--orange));
  border-radius: 999px;
  padding: 5px 10px;
}
ul { padding-left: 18px; }
code { color: #9cffeb; }
@media (max-width: 680px) {
  .wrapper { padding: 16px; }
  .hero { padding: 20px; }
}`
	w.Header().Set("Content-Type", "text/css")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(css))
}

func handleCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, `{"items":[{"name":"Enterprise Gateway","price":"$129"},{"name":"Observability Suite","price":"$299"}]}`)
}

func handleTrapReflection(w http.ResponseWriter, r *http.Request) {
	payload := firstNonEmpty(r.URL.Query().Get("q"), r.URL.Query().Get("input"), r.URL.Query().Get("ssi"), "<none>")
	writeHTML(w, 200, fmt.Sprintf(`<html><body><h1>Reflection Trap</h1><p>This endpoint only reflects user input.</p><pre>%s</pre></body></html>`, payload))
}

func handleTrapSoft404(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, 200, `<html><head><title>404 Not Found</title></head><body><h1>Page Not Found</h1><p>admin root dashboard password</p></body></html>`)
}

func handleTrapSQLStatic(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, 200, `<html><body><h1>Trap SQL Static</h1><p>You have an error in your SQL syntax near static content.</p></body></html>`)
}

func maybeServeSensitiveFile(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	if c, ok := sensitiveRoutes[path]; ok {
		writeByType(w, c.status, c.contentType, c.body)
		return true
	}

	switch {
	case strings.HasPrefix(path, "/backup/") || strings.HasPrefix(path, "/logs/"):
		writeHTML(w, 200, `<html><body><h1>Index of /backup</h1><a href="/backup.sql">backup.sql</a></body></html>`)
		return true
	case path == "/backup.zip" || path == "/data.zip" || path == "/sql.zip" || path == "/users.xlsx":
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("PK\x03\x04mock-binary"))
		return true
	case path == "/api/":
		writeJSON(w, 200, `{"status":"api root"}`)
		return true
	case path == "/robots.txt":
		writeText(w, 200, "User-agent: *\nDisallow: /admin\n")
		return true
	case path == "/phpinfo.php":
		writeHTML(w, 200, `<html><body><h1>PHP Version 8.2.8</h1></body></html>`)
		return true
	case path == "/wp-login.php":
		writeHTML(w, 200, `<html><body><input name="wp-submit" value="Log In"></body></html>`)
		return true
	case path == "/wp-admin/":
		handleInternalProtected(w, r)
		return true
	}

	return false
}

func maybeServeLFIOrWrapper(w http.ResponseWriter, r *http.Request) bool {
	full := strings.ToLower(r.URL.RequestURI())

	if strings.Contains(full, "etc/passwd") || strings.Contains(full, "file:///etc/passwd") || strings.Contains(full, "expect://id") || strings.Contains(full, "gopher://") {
		writeText(w, 200, "root:x:0:0:root:/root:/bin/bash\nuid=0(root) gid=0(root)")
		return true
	}
	if strings.Contains(full, "windows/win.ini") || strings.Contains(full, "winnt/win.ini") || strings.Contains(full, "boot.ini") {
		writeText(w, 200, "[fonts]\n[boot loader]\n")
		return true
	}
	if strings.Contains(full, "php://filter/convert.base64-encode/resource=index.php") {
		snippet := "<?php $db='prod'; class Config {} return array('k'=>'v');"
		encoded := base64.StdEncoding.EncodeToString([]byte(snippet))
		writeText(w, 200, encoded)
		return true
	}
	if strings.Contains(full, "php://filter/read=string.rot13/resource=index.php") {
		writeText(w, 200, "<?cuc cevag('ebg13'); ?>")
		return true
	}
	if strings.Contains(full, "data://text/plain;base64") {
		writeText(w, 200, "BhyakuganRCE")
		return true
	}
	if strings.Contains(full, ".env") && (strings.Contains(full, "%2e%2e") || strings.Contains(full, "index.php/%2e%2e") || strings.HasPrefix(strings.ToLower(r.URL.Path), "/..")) {
		writeText(w, 200, "APP_KEY=base64:local-app-key\nAPP_ENV=production\nDB_HOST=127.0.0.1\nDB_DATABASE=core\nDB_USERNAME=root\nDB_PASSWORD=toor\n")
		return true
	}
	if strings.Contains(full, "/proc/version") {
		writeText(w, 200, "Linux version 6.8.9-localhost")
		return true
	}
	if strings.Contains(full, "/proc/self/environ") {
		writeText(w, 200, "HTTP_USER_AGENT=Mozilla/5.0\n")
		return true
	}
	if strings.Contains(full, "/proc/net/tcp") {
		writeText(w, 200, "sl  local_address rem_address")
		return true
	}

	return false
}

func maybeServeXPathOrXSLT(w http.ResponseWriter, r *http.Request) bool {
	raw := strings.ToLower(r.URL.RawQuery)

	if strings.Contains(raw, "xpath") || strings.Contains(raw, "domxpath") {
		writeText(w, 200, "XPathException: invalid expression")
		return true
	}

	if queryContains(r, "system-property('xsl:vendor')") || queryContains(r, `system-property("xsl:vendor")`) {
		writeText(w, 200, `<?xml version="1.0"?><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">libxslt vendor output</xsl:stylesheet>`)
		return true
	}
	if queryContains(r, "document('/etc/passwd')") || queryContains(r, "php:function('readfile','/etc/passwd')") {
		writeText(w, 200, "root:x:0:0:root:/root:/bin/bash")
		return true
	}

	if hasXPathBypass(r) {
		writeHTML(w, 200, `<html><body><h1>admin account</h1><p>password list disclosed</p></body></html>`)
		return true
	}

	return false
}

func handleInternalProtected(w http.ResponseWriter, r *http.Request) {
	if !hasInternalBypassHeader(r) {
		writeText(w, 403, "Forbidden")
		return
	}
	writeHTML(w, 200, `<html><body><h1>admin dashboard</h1><p>config root access granted</p></body></html>`)
}

func hasInternalBypassHeader(r *http.Request) bool {
	for _, k := range internalHeaderKeys {
		v := strings.ToLower(r.Header.Get(k))
		if strings.Contains(v, "127.0.0.1") {
			return true
		}
	}
	return false
}

func isProxyInternalPath(path string) bool {
	for _, p := range []string{"/admin", "/internal", "/stats", "/server-status", "/config", "/api/v1/admin", "/wp-admin/"} {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func isWCDPath(r *http.Request) bool {
	path := strings.ToLower(r.URL.Path)
	rawQuery := strings.ToLower(r.URL.RawQuery)
	candidates := []string{"test.css", "test.js", "test.avif", "test.png", "test.jpg", "test.svg"}
	for _, c := range candidates {
		if strings.Contains(path, c) || strings.Contains(rawQuery, c) {
			return true
		}
	}
	return false
}

func isNoSQLPayload(r *http.Request) bool {
	raw := strings.ToLower(r.URL.RawQuery)
	return strings.Contains(raw, "$ne") || strings.Contains(raw, "$gt") || strings.Contains(raw, "$regex") || strings.Contains(raw, "$nin")
}

func isNoSQLBody(body string) bool {
	return strings.Contains(body, "$ne") || strings.Contains(body, "$gt") || strings.Contains(body, "$regex") || strings.Contains(body, "$nin")
}

func hasXPathBypass(r *http.Request) bool {
	for _, vals := range r.URL.Query() {
		for _, v := range vals {
			c := strings.ToLower(v)
			if strings.Contains(c, "' or '1'='1") ||
				strings.Contains(c, "' or ''='") ||
				strings.Contains(c, "//*") ||
				strings.Contains(c, "count(/*)=1") ||
				strings.Contains(c, "count(/*)>0") ||
				strings.Contains(c, "string-length(name(/*[1]))=4") ||
				strings.Contains(c, "substring(name(/*[1]),1,1)='r'") ||
				strings.Contains(c, "name()='username'") {
				return true
			}
		}
	}
	return false
}

func hasArrayParam(values map[string][]string) bool {
	for k := range values {
		if strings.Contains(k, "[") || strings.Contains(k, "]") {
			return true
		}
	}
	return false
}

func hasHeaderTemplatePayload(r *http.Request) bool {
	referer := r.Header.Get("Referer")
	ua := r.Header.Get("User-Agent")
	marker := "{{readFile \"/etc/passwd\"}}"
	return strings.Contains(referer, marker) || strings.Contains(ua, marker)
}

func queryContains(r *http.Request, needle string) bool {
	n := strings.ToLower(needle)
	for _, vals := range r.URL.Query() {
		for _, v := range vals {
			if strings.Contains(strings.ToLower(v), n) {
				return true
			}
		}
	}
	return false
}

func jwtAlgFromHeader(authHeader string) string {
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return ""
	}
	token := strings.TrimSpace(authHeader[7:])
	parts := strings.Split(token, ".")
	if len(parts) < 1 {
		return ""
	}
	decoded, err := decodeJWTPart(parts[0])
	if err != nil {
		return ""
	}
	low := strings.ToLower(decoded)
	for _, candidate := range []string{"none", "nOne", "None", "NONE", "nOnE"} {
		if strings.Contains(low, fmt.Sprintf(`"alg":"%s"`, strings.ToLower(candidate))) {
			return candidate
		}
	}
	if strings.Contains(low, `"alg":"none"`) {
		return "none"
	}
	return ""
}

func decodeJWTPart(part string) (string, error) {
	part = strings.TrimSpace(part)
	if part == "" {
		return "", fmt.Errorf("empty")
	}
	if mod := len(part) % 4; mod != 0 {
		part += strings.Repeat("=", 4-mod)
	}
	decoded, err := base64.URLEncoding.DecodeString(part)
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(part, "="))
		if err != nil {
			return "", err
		}
	}
	return string(decoded), nil
}

func baseDashboardHTML(wcd bool) string {
	stateTag := "Live Enterprise Surface"
	if wcd {
		stateTag = "Cached Dynamic Response"
	}
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Advanced Localhost Commerce</title>
  <link rel="stylesheet" href="/static/theme.css" />
</head>
<body>
  <div class="wrapper">
    <section class="hero">
      <span class="tag">%s</span>
      <h1>Adaptive Commerce Control Plane</h1>
      <p>
        csrf_token=labcsrf_9f88x, sessionid=web-flow-token, jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.signature
      </p>
      <p id="jwt-token"></p>
      <div class="grid">
        <article class="card">
          <h3>Core APIs</h3>
          <ul>
            <li><a href="/api/login?user=guest&pass=guest">Auth API</a></li>
            <li><a href="/api/fetch?url=https://example.org/data.json">Fetcher API</a></li>
            <li><a href="/vuln/sql?id=1">SQL backend endpoint</a></li>
            <li><a href="/vuln/oracle?id=1">Oracle backend endpoint</a></li>
          </ul>
        </article>
        <article class="card">
          <h3>Template + Auth</h3>
          <ul>
            <li><a href="/template?q=hello">Template renderer</a></li>
            <li><a href="/auth/login?user=guest&pass=guest">Login portal</a></li>
            <li><a href="/vuln/eval?cmd=whoami">Command diagnostics</a></li>
            <li><a href="/vuln/xpath?user=guest">XPath filter endpoint</a></li>
            <li><a href="/vuln/xslt?xml=%%3Cxsl%%3E%%3C%%2Fxsl%%3E">XSLT transform endpoint</a></li>
          </ul>
        </article>
        <article class="card">
          <h3>Exposure Surface</h3>
          <ul>
            <li><a href="/.env">Environment config</a></li>
            <li><a href="/.git/HEAD">Git metadata</a></li>
            <li><a href="/backup.sql">Backup dump</a></li>
            <li><a href="/server-status">Server status</a></li>
            <li><a href="/redirect?url=https://google.com">Open Redirect</a></li>
            <li><a href="/api/upload">File Upload API</a></li>
          </ul>
        </article>
        <article class="card">
          <h3>Previous-Issue Lab</h3>
          <ul>
            <li><a href="/graphql">GraphQL endpoint (introspection enabled)</a></li>
            <li><a href="/graphiql">GraphiQL UI</a></li>
            <li><a href="/ws">WebSocket cross-origin handshake endpoint</a></li>
            <li><a href="/vuln/xslt?style=sample&template=sample&xml=sample&xslt=sample">XSLT multi-parameter surface</a></li>
          </ul>
        </article>
        <article class="card">
          <h3>Scanner Trap Zone</h3>
          <ul>
            <li><a href="/trap/reflection?q=payload">Reflection trap</a></li>
            <li><a href="/trap/soft404">Soft404 trap</a></li>
            <li><a href="/trap/sql-static?id=1">Static SQL error trap</a></li>
          </ul>
        </article>
      </div>
      <h3>Catalog</h3>
      <ul id="catalog"></ul>
    </section>
  </div>
  <script src="/static/config.js"></script>
  <script src="/static/auth-utils.js"></script>
  <script src="/static/app.js"></script>
</body>
</html>`, stateTag)
}

func writeByType(w http.ResponseWriter, status int, contentType, body string) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func writeText(w http.ResponseWriter, status int, body string) {
	writeByType(w, status, "text/plain; charset=utf-8", body)
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	writeByType(w, status, "text/html; charset=utf-8", body)
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	writeByType(w, status, "application/json", body)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func atoiWithDefault(v string, fallback int) int {
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func handleGoogleMock(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		writeJSON(w, 401, `{"error":{"message":"API key not found."}}`)
		return
	}

	if strings.Contains(key, "VulnerableKey") {
		writeJSON(w, 200, `{"status":"OK","results":[]}`)
	} else if strings.Contains(key, "RestrictedKey") {
		writeJSON(w, 403, `{"error":{"message":"This API project is not authorized to use this API.","status":"PERMISSION_DENIED"}}`)
	} else {
		writeJSON(w, 401, `{"error":{"message":"API key not valid."}}`)
	}
}

func handleOpenRedirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		target = r.URL.Query().Get("next")
	}
	if target != "" {
		http.Redirect(w, r, target, 302)
		return
	}
	writeHTML(w, 200, "<html><body><h1>Redirect Portal</h1></body></html>")
}

func handleFileUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, `{"error":"Method not allowed"}`)
		return
	}
	
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		writeJSON(w, 400, `{"error":"Unable to parse form"}`)
		return
	}
	
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, 400, `{"error":"File not found in request"}`)
		return
	}
	defer file.Close()
	
	writeJSON(w, 201, fmt.Sprintf(`{"status":"success", "message":"File %s uploaded successfully"}`, header.Filename))
}

