#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

PORT="${PORT:-18084}"
TIMEOUT="${TIMEOUT:-8}"
DEPTH="${DEPTH:-2}"
MODE="${MODE:-aggressive}"
TARGET="http://127.0.0.1:${PORT}"
OUT_BIN="/tmp/bhyakugan_localhost_fullstack"
MOCK_LOG="/tmp/bhyakugan_mock_localhost.log"
SCAN_LOG="/tmp/bhyakugan_scan_localhost.log"

cleanup() {
  if [[ -n "${MOCK_PID:-}" ]]; then
    kill "$MOCK_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "[*] Building bhyakugan binary"
GOCACHE=/tmp/go-build go build -o "$OUT_BIN" cmd/bhyakugan/main.go

echo "[*] Starting localhost mockserver on :$PORT"
MOCKSERVER_PORT="$PORT" GOCACHE=/tmp/go-build go run cmd/mockserver/main.go >"$MOCK_LOG" 2>&1 &
MOCK_PID=$!
sleep 1

if ! kill -0 "$MOCK_PID" >/dev/null 2>&1; then
  echo "[-] Mockserver failed to start"
  cat "$MOCK_LOG"
  exit 1
fi

echo "[*] Running bhyakugan against $TARGET"
"$OUT_BIN" -target "$TARGET" -depth "$DEPTH" -timeout "$TIMEOUT" -mode "$MODE" >"$SCAN_LOG" 2>&1 || true

REPORT_FILE="bhyakugan-output/report_http_127.0.0.1_${PORT}.html"
if [[ ! -f "$REPORT_FILE" ]]; then
  # Backward compatibility for legacy timestamp-based reports.
  REPORT_FILE="$(ls -1t bhyakugan-output/report_*"${PORT}"_*.html 2>/dev/null | head -n 1 || true)"
fi
if [[ -z "$REPORT_FILE" ]]; then
  echo "[-] Report file not found for localhost run"
  tail -n 120 "$SCAN_LOG" || true
  exit 1
fi

echo "[*] Latest report: $REPORT_FILE"

declare -a REQUIRED_PATTERNS=(
  "Local File Inclusion (LFI)"
  "SQL Injection"
  "NoSQL Injection"
  "SSRF Injection"
  "Server-Side Template Injection"
  "Prototype Pollution"
  "Improper Trust in HTTP Headers (Proxy Bypass)"
  "SAML Vulnerability|SAML Endpoints Detected"
  "GraphQL Introspection|GraphQL Schema Discovery Exposure"
  "Git Exposure"
  "Cross-Site WebSocket Hijacking|WebSocket Origin Policy Misconfiguration"
  "PHP Type Juggling"
  "ORM Leak"
  "XSLT Injection|Template Engine Injection"
  "XPath Injection|XML Query Injection"
  "OS Command Injection (Time-Based)"
  "JWT None Algorithm"
)

missing=0
for pattern in "${REQUIRED_PATTERNS[@]}"; do
  found=0
  IFS='|' read -r -a options <<< "$pattern"
  for opt in "${options[@]}"; do
    if grep -Fq "$opt" "$REPORT_FILE"; then
      found=1
      break
    fi
  done
  if [[ $found -eq 1 ]]; then
    echo "[+] Found expected finding marker: $pattern"
  else
    echo "[-] Missing expected finding marker: $pattern"
    missing=1
  fi
done

declare -a TRAP_PATHS=(
  "/trap/reflection"
  "/trap/soft404"
  "/trap/sql-static"
)

trap_fp=0
for trap_path in "${TRAP_PATHS[@]}"; do
  if grep -Fq "$trap_path" "$REPORT_FILE"; then
    echo "[-] FALSE POSITIVE trap triggered in report: $trap_path"
    trap_fp=1
  else
    echo "[+] Trap clean (not reported): $trap_path"
  fi
done

quality_fail=0

# Anti over-cluster checks (single root-cause row for these classes in report table)
xslt_rows_primary="$(grep -Fc '<td class="col-type">XSLT Injection</td>' "$REPORT_FILE" || true)"
xslt_rows_cluster="$(grep -Fc '<td class="col-type">Template Engine Injection</td>' "$REPORT_FILE" || true)"
xslt_rows=$((xslt_rows_primary + xslt_rows_cluster))
xpath_rows_primary="$(grep -Fc '<td class="col-type">XPath Injection</td>' "$REPORT_FILE" || true)"
xpath_rows_rootcause="$(grep -Fc '<td class="col-type">XML Query Injection</td>' "$REPORT_FILE" || true)"
xpath_rows=$((xpath_rows_primary + xpath_rows_rootcause))
ws_rows_primary="$(grep -Fc '<td class="col-type">Cross-Site WebSocket Hijacking</td>' "$REPORT_FILE" || true)"
ws_rows_rootcause="$(grep -Fc '<td class="col-type">WebSocket Origin Policy Misconfiguration</td>' "$REPORT_FILE" || true)"
ws_rows=$((ws_rows_primary + ws_rows_rootcause))

if [[ "${xslt_rows}" -gt 1 ]]; then
  echo "[-] Over-cluster detected: XSLT Injection rows=$xslt_rows (expected <=1)"
  quality_fail=1
else
  echo "[+] XSLT root-cause clustering OK (rows=$xslt_rows)"
fi

if [[ "${xpath_rows}" -gt 1 ]]; then
  echo "[-] Over-cluster detected: XPath Injection rows=$xpath_rows (expected <=1)"
  quality_fail=1
else
  echo "[+] XPath root-cause clustering OK (rows=$xpath_rows)"
fi

if [[ "${ws_rows}" -gt 1 ]]; then
  echo "[-] Over-cluster detected: WebSocket misconfig rows=$ws_rows (expected <=1)"
  quality_fail=1
else
  echo "[+] WebSocket clustering OK (rows=$ws_rows)"
fi

# Evidence content checks for previous issues
if grep -Fq "Affected parameters: style, template, xml, xsl, xslt" "$REPORT_FILE"; then
  echo "[+] XSLT affected-parameter evidence found"
else
  echo "[-] Missing XSLT affected-parameter evidence"
  quality_fail=1
fi

if grep -Fq "Affected parameters: id, name, query, search, user, xml" "$REPORT_FILE"; then
  echo "[+] XPath affected-parameter evidence found"
else
  echo "[-] Missing XPath affected-parameter evidence"
  quality_fail=1
fi

if grep -Fq "configuration exposure only; no auth bypass or data exposure proof was observed" "$REPORT_FILE"; then
  echo "[+] GraphQL introspection classified as configuration exposure"
else
  echo "[-] GraphQL introspection hardening text missing"
  quality_fail=1
fi

if grep -Fq "policy misconfiguration signal only; no authenticated action, cookie replay, or csrf-over-websocket proof was observed" "$REPORT_FILE" || \
   grep -Fq "Policy misconfiguration signal only; no authenticated action, cookie replay, or CSRF-over-WebSocket proof was observed." "$REPORT_FILE"; then
  echo "[+] WebSocket misconfiguration-only evidence text found"
else
  echo "[-] WebSocket exploitability hardening text missing"
  quality_fail=1
fi

if grep -Fq "Evidence Quality:" "$REPORT_FILE"; then
  echo "[+] Evidence quality scoring present in report"
else
  echo "[-] Evidence quality scoring missing in report"
  quality_fail=1
fi

echo "[*] Scan log: $SCAN_LOG"
echo "[*] Mock log: $MOCK_LOG"

if [[ $missing -ne 0 || $trap_fp -ne 0 || $quality_fail -ne 0 ]]; then
  echo "[-] Localhost regression failed"
  exit 1
fi

echo "[+] Localhost regression passed"
