#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

PATT_PATH="${PATT_PATH:-/home/yupiyy/tools/bug/PayloadsAllTheThings}"
OUT_BIN="/tmp/bhyakugan_regression"

echo "[*] Building scanner"
GOCACHE=/tmp/go-build go build -o "$OUT_BIN" cmd/bhyakugan/main.go

echo "[*] Starting mockserver"
GOCACHE=/tmp/go-build go run cmd/mockserver/main.go >/tmp/bhyakugan_mock.log 2>&1 &
MS_PID=$!
trap 'kill $MS_PID >/dev/null 2>&1 || true' EXIT
sleep 1

echo "[*] Running strict mode"
"$OUT_BIN" -target http://localhost:8084 -depth 1 -timeout 5 -mode strict -patt "$PATT_PATH" >/tmp/bhyakugan_strict.log 2>&1 || true

echo "[*] Running balanced mode"
"$OUT_BIN" -target http://localhost:8084 -depth 1 -timeout 5 -mode balanced -patt "$PATT_PATH" >/tmp/bhyakugan_balanced.log 2>&1 || true

echo "[*] Running strict+fast mode"
"$OUT_BIN" -target http://localhost:8084 -depth 1 -timeout 5 -mode strict -fast -patt "$PATT_PATH" >/tmp/bhyakugan_fast.log 2>&1 || true

echo "[*] Done. Logs:"
echo " - /tmp/bhyakugan_strict.log"
echo " - /tmp/bhyakugan_balanced.log"
echo " - /tmp/bhyakugan_fast.log"
echo " - /tmp/bhyakugan_mock.log"
