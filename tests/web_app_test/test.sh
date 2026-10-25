#!/usr/bin/env bash
# End-to-end tests: real clients in client_ns -> Aethon on veth0 -> nginx -> Node.
# Prerequisites: ./start.sh is running and Aethon is running (sudo ./build/src/afxdp_control veth0).
#
# Usage: ./test.sh [--netem "delay 50ms loss 2%"] [--full] [--load]
#   --netem SPEC  apply tc netem on the client side for the whole run (default spec: "delay 50ms loss 2%")
#   --full        also transfer the 50 MB file
#   --load        run wrk load tests (through Aethon vs. nginx directly)
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
RUN_DIR="${RUN_DIR:-/tmp/aethon_web_app_test}"
SERVER_IP=192.168.50.1
TLS_HOST=test.local
NETEM=""
FULL=0
LOAD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --netem)
      if [[ $# -gt 1 && "$2" != --* ]]; then NETEM="$2"; shift; else NETEM="delay 50ms loss 2%"; fi ;;
    --full) FULL=1 ;;
    --load) LOAD=1 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
  shift
done

PASS=0; FAIL=0; SKIP=0
pass() { echo -e "  \033[92mPASS\033[0m $*"; PASS=$((PASS + 1)); }
fail() { echo -e "  \033[91mFAIL\033[0m $*"; FAIL=$((FAIL + 1)); }
skip() { echo -e "  \033[93mSKIP\033[0m $*"; SKIP=$((SKIP + 1)); }
section() { echo -e "\n\033[1m== $* ==\033[0m"; }

C() { sudo ip netns exec client_ns "$@"; }                 # run inside the client namespace
TIMEOUT=$([[ -n "$NETEM" ]] && echo 300 || echo 60)
CURL=(curl -sS --max-time "$TIMEOUT")
TLS=(--resolve "$TLS_HOST:443:$SERVER_IP" -k)

expected_sha() { awk -v f="./$1" '$2 == f {print $1}' "$RUN_DIR/files/SHA256SUMS"; }

check_sha() {   # check_sha <label> <expected> <curl args...>
  local label="$1" want="$2"; shift 2
  local got
  got=$(C "${CURL[@]}" "$@" | sha256sum | cut -d' ' -f1)
  if [[ "$got" == "$want" ]]; then pass "$label"; else fail "$label (sha256 mismatch: got ${got:0:16}…, want ${want:0:16}…)"; fi
}

# ---------------------------------------------------------------- preflight
sudo -v || exit 1
ip netns list | grep -qw client_ns || { echo "client_ns missing: run ./start.sh first"; exit 1; }
curl -fsS "http://127.0.0.1:8080/api/health" >/dev/null 2>&1 || { echo "nginx/node not running: run ./start.sh first"; exit 1; }
pgrep -f afxdp_control >/dev/null || echo -e "\033[93mwarning: afxdp_control does not seem to be running; tests will fail\033[0m"
[[ -f "$RUN_DIR/files/SHA256SUMS" ]] || { echo "missing test files: run ./start.sh"; exit 1; }

if [[ -n "$NETEM" ]]; then
  echo "applying netem on veth1: $NETEM"
  C tc qdisc replace dev veth1 root netem $NETEM
  trap 'C tc qdisc del dev veth1 root 2>/dev/null' EXIT
fi

SIZES=(1mb 5mb); [[ $FULL -eq 1 ]] && SIZES+=(50mb)

# ---------------------------------------------------------------- plain HTTP
section "HTTP (port 80) -> Aethon -> nginx -> node"

body=$(C "${CURL[@]}" "http://$SERVER_IP/")
[[ "$body" == *"Aethon Notes"* ]] && pass "static index page" || fail "static index page"

body=$(C "${CURL[@]}" "http://$SERVER_IP/api/health")
[[ "$body" == *'"ok":true'* ]] && pass "API health via nginx proxy" || fail "API health ($body)"

note="note-$RANDOM-$$"
C "${CURL[@]}" -X POST -H 'Content-Type: application/json' -d "{\"text\":\"$note\"}" "http://$SERVER_IP/api/notes" >/dev/null
body=$(C "${CURL[@]}" "http://$SERVER_IP/api/notes")
[[ "$body" == *"$note"* ]] && pass "create + list note (POST/GET JSON)" || fail "create + list note"

# 5 requests on one keep-alive connection
body=$(C "${CURL[@]}" "http://$SERVER_IP/api/health" "http://$SERVER_IP/api/health" "http://$SERVER_IP/api/health" \
       "http://$SERVER_IP/api/health" "http://$SERVER_IP/api/health")
count=$(grep -o '"ok":true' <<< "$body" | wc -l)
[[ "$count" -eq 5 ]] && pass "5 requests on one keep-alive connection" || fail "keep-alive ($count/5 responses)"

for s in "${SIZES[@]}"; do
  check_sha "static download $s (nginx sendfile)" "$(expected_sha "$s.bin")" "http://$SERVER_IP/files/$s.bin"
done
check_sha "streamed download 5mb (node -> nginx)" "$(expected_sha 5mb.bin)" "http://$SERVER_IP/api/file/5mb.bin"

up="$RUN_DIR/upload_20mb.bin"
[[ -f "$up" ]] || head -c $((20 * 1024 * 1024)) /dev/urandom > "$up"
want=$(sha256sum "$up" | cut -d' ' -f1)
body=$(C "${CURL[@]}" --data-binary @"$up" -H 'Content-Type: application/octet-stream' "http://$SERVER_IP/api/upload")
[[ "$body" == *"$want"* ]] && pass "20 MB upload, backend sha256 matches" || fail "20 MB upload ($body)"

body=$(C "${CURL[@]}" "http://$SERVER_IP/api/slow?ms=1500")
[[ "$body" == *'"slept_ms":1500'* ]] && pass "slow backend response (1.5 s)" || fail "slow backend ($body)"

# ---------------------------------------------------------------- security
section "Security"

body=$(C curl -sS --max-time 10 "http://$SERVER_IP/api/health?f=/etc/passwd" 2>&1)
[[ "$body" != *'"ok":true'* ]] && pass "DPI blocks /etc/passwd (${body:0:60})" || fail "DPI did NOT block /etc/passwd"

if C curl -sS --max-time 3 "http://$SERVER_IP:8080/" >/dev/null 2>&1; then
  fail "nginx reachable directly on :8080 (bypasses Aethon); bind it to 127.0.0.1"
else
  pass "backend not reachable directly (only through Aethon)"
fi

# ---------------------------------------------------------------- TLS
section "HTTPS (port 443) -> Aethon TLS termination -> nginx"

if grep -q "^$SERVER_IP:443 " "$ROOT/rules/services.conf"; then
  body=$(C "${CURL[@]}" "${TLS[@]}" "https://$TLS_HOST/api/health")
  [[ "$body" == *'"ok":true'* ]] && pass "TLS API health" || fail "TLS API health ($body)"

  for s in "${SIZES[@]}"; do
    check_sha "TLS download $s" "$(expected_sha "$s.bin")" "${TLS[@]}" "https://$TLS_HOST/files/$s.bin"
  done

  body=$(C "${CURL[@]}" "${TLS[@]}" --data-binary @"$up" "https://$TLS_HOST/api/upload")
  [[ "$body" == *"$want"* ]] && pass "TLS 20 MB upload, sha256 matches" || fail "TLS 20 MB upload ($body)"

  body=$(C curl -sS --max-time 10 "${TLS[@]}" "https://$TLS_HOST/api/health?f=/etc/passwd" 2>&1)
  [[ "$body" != *'"ok":true'* ]] && pass "DPI blocks /etc/passwd inside TLS" || fail "DPI did NOT block /etc/passwd inside TLS"

  blocked=$(grep -m1 -v '^\s*\(#\|$\)' "$ROOT/rules/blocked_domains.txt" 2>/dev/null || true)
  if [[ -n "$blocked" ]]; then
    body=$(C curl -sS --max-time 10 -k --resolve "$blocked:443:$SERVER_IP" "https://$blocked/api/health" 2>&1)
    [[ "$body" != *'"ok":true'* ]] && pass "SNI block for $blocked" || fail "SNI $blocked was NOT blocked"
    body=$(C curl -sS --max-time 10 -k --resolve "api.$blocked:443:$SERVER_IP" "https://api.$blocked/api/health" 2>&1)
    [[ "$body" != *'"ok":true'* ]] && pass "SNI block for subdomain api.$blocked" || fail "SNI api.$blocked was NOT blocked"
  else
    skip "SNI block (rules/blocked_domains.txt is empty)"
  fi
else
  skip "TLS tests ($SERVER_IP:443 not in rules/services.conf)"
fi

# ---------------------------------------------------------------- load
if [[ $LOAD -eq 1 ]]; then
  section "Load (wrk, 10 s each)"
  if command -v wrk >/dev/null; then
    summarize() { grep -E "Requests/sec|Latency|Socket errors|Non-2xx" | sed 's/^/    /'; }
    echo "  through Aethon: http://$SERVER_IP/"
    C wrk -t2 -c100 -d10s --latency "http://$SERVER_IP/" | summarize
    echo "  through Aethon: http://$SERVER_IP/api/health"
    C wrk -t2 -c100 -d10s --latency "http://$SERVER_IP/api/health" | summarize
    echo "  baseline, nginx directly: http://127.0.0.1:8080/"
    wrk -t2 -c100 -d10s --latency "http://127.0.0.1:8080/" | summarize
    echo "  Aethon RSS after load: $(ps -o rss= -C afxdp_control | awk '{s+=$1} END {printf "%.1f MB", s/1024}')"
  else
    skip "wrk not installed (sudo apt install -y wrk)"
  fi
fi

# ---------------------------------------------------------------- summary
echo
echo -e "\033[1mResult: $PASS passed, $FAIL failed, $SKIP skipped\033[0m${NETEM:+  (netem: $NETEM)}"
[[ $FAIL -eq 0 ]]
