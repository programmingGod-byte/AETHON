#!/usr/bin/env bash
# Torture suite for Aethon: network chaos in both directions, concurrency, connection churn,
# protocol edge cases and adversarial clients. Aethon must stay correct and alive throughout.
#
# Prerequisites: ./start.sh running, Aethon running (sudo ./build/src/afxdp_control veth0).
#
# Usage: ./torture.sh [--quick] [--long] [--only SECTION]
#   SECTION: chaos | concurrency | churn | edges | attacks
#   --quick  smaller sizes and counts (about 5 minutes)
#   --long   adds 200 MB download / 100 MB upload and a 10 s SYN flood
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="${RUN_DIR:-/tmp/aethon_web_app_test}"
TOOL="$DIR/tools/torture_client.py"
SERVER_IP=192.168.50.1
TLS=(--resolve "test.local:443:$SERVER_IP" -k)
QUICK=0; LONG=0; ONLY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) QUICK=1 ;;
    --long) LONG=1 ;;
    --only) ONLY="$2"; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
  shift
done

PASS=0; FAIL=0; INFO=0
pass() { echo -e "  \033[92mPASS\033[0m $*"; PASS=$((PASS + 1)); }
fail() { echo -e "  \033[91mFAIL\033[0m $*"; FAIL=$((FAIL + 1)); }
info() { echo -e "  \033[96mINFO\033[0m $*"; INFO=$((INFO + 1)); }
section() { echo -e "\n\033[1m== $* ==\033[0m"; }
want() { [[ -z "$ONLY" || "$ONLY" == "$1" ]]; }

C() { sudo ip netns exec client_ns "$@"; }
sha_of() { awk -v f="./$1" '$2 == f {print $1}' "$RUN_DIR/files/SHA256SUMS"; }
rss_mb() { ps -o rss= -C afxdp_control | awk '{s += $1} END {printf "%.1f", s / 1024}'; }

# Run the python tool inside client_ns; PASS/FAIL from its exit code, message from its output
tool() {  # tool <label> <subcommand args...>
  local label="$1"; shift
  local out
  out=$(C timeout 600 python3 "$TOOL" "$@" 2>&1 | tail -1)
  if [[ "$out" == OK* ]]; then pass "$label: ${out#OK }"; else fail "$label: ${out#BAD }"; fi
}

curl_sha() {  # curl_sha <label> <expected sha> <curl args...>
  local label="$1" want="$2"; shift 2
  local got
  got=$(C curl -sS --max-time 600 "$@" 2>/dev/null | sha256sum | cut -d' ' -f1)
  [[ "$got" == "$want" ]] && pass "$label" || fail "$label (sha256 mismatch or transfer failed)"
}

upload_sha() {  # upload_sha <label> <file> <url> [curl args...]
  local label="$1" file="$2" url="$3"; shift 3
  local want body
  want=$(sha256sum "$file" | cut -d' ' -f1)
  body=$(C curl -sS --max-time 600 "$@" --data-binary @"$file" -H 'Content-Type: application/octet-stream' "$url" 2>&1)
  [[ "$body" == *"$want"* ]] && pass "$label" || fail "$label (${body:0:80})"
}

alive_check() {
  local h1 h2
  if ! pgrep -x afxdp_control >/dev/null; then fail "Aethon process is GONE (crashed)"; return; fi
  h1=$(C curl -sS --max-time 10 "http://$SERVER_IP/api/health" 2>&1)
  h2=$(C curl -sS --max-time 10 "${TLS[@]}" "https://test.local/api/health" 2>&1)
  if [[ "$h1" == *'"ok":true'* && "$h2" == *'"ok":true'* ]]; then
    pass "Aethon alive and serving HTTP + HTTPS (RSS $(rss_mb) MB)"
  else
    fail "Aethon alive but not serving (http: ${h1:0:40} | https: ${h2:0:40})"
  fi
}

# ------------------------------------------------------------------ bidirectional netem
# Client egress shapes uploads/ACKs. Aethon's AF_XDP TX bypasses veth0's qdisc, so traffic
# towards the client is shaped on the client's ingress, redirected through an ifb device.
chaos_on() {
  local spec="$1"
  C tc qdisc replace dev veth1 root netem $spec
  C ip link add ifb0 type ifb 2>/dev/null || true
  C ip link set ifb0 up
  C tc qdisc replace dev veth1 handle ffff: ingress
  C tc filter replace dev veth1 parent ffff: pref 1 matchall action mirred egress redirect dev ifb0
  C tc qdisc replace dev ifb0 root netem $spec
}
chaos_off() {
  C tc qdisc del dev veth1 root 2>/dev/null
  C tc qdisc del dev veth1 ingress 2>/dev/null
  C ip link del ifb0 2>/dev/null
  true
}
trap chaos_off EXIT

# ------------------------------------------------------------------ preflight
sudo -v || exit 1
pgrep -x afxdp_control >/dev/null || { echo "Aethon is not running: sudo ./build/src/afxdp_control veth0"; exit 1; }
curl -fsS http://127.0.0.1:8080/api/health >/dev/null 2>&1 || { echo "web stack not running: ./start.sh"; exit 1; }
sudo modprobe ifb numifbs=0 2>/dev/null || true
C sysctl -qw net.core.txrehash=0
chaos_off

SIZE=5mb; [[ $QUICK -eq 1 ]] && SIZE=1mb
FILE="$RUN_DIR/files/$SIZE.bin"
SHA=$(sha_of "$SIZE.bin")
echo "Aethon RSS at start: $(rss_mb) MB"

# ------------------------------------------------------------------ 1. chaos
if want chaos; then
  section "Network chaos in both directions ($SIZE transfers, HTTP + HTTPS, up + down)"
  PROFILES=(
    "reorder|delay 10ms reorder 25% 50%"
    "duplicate|duplicate 10%"
    "jitter (reorders)|delay 20ms 15ms"
    "burst loss|loss 3% 25%"
    "bandwidth cap|rate 20mbit delay 10ms"
    "corruption|corrupt 0.5%"
  )
  [[ $QUICK -eq 0 ]] && PROFILES+=("heavy loss 10%|loss 10%")
  for entry in "${PROFILES[@]}"; do
    name="${entry%%|*}"; spec="${entry#*|}"
    echo "  -- $name ($spec)"
    chaos_on "$spec"
    curl_sha   "[$name] HTTP download"  "$SHA" "http://$SERVER_IP/files/$SIZE.bin"
    upload_sha "[$name] HTTP upload"    "$FILE" "http://$SERVER_IP/api/upload"
    curl_sha   "[$name] HTTPS download" "$SHA" "${TLS[@]}" "https://test.local/files/$SIZE.bin"
    upload_sha "[$name] HTTPS upload"   "$FILE" "https://test.local/api/upload" "${TLS[@]}"
    chaos_off
  done
  alive_check
fi

# ------------------------------------------------------------------ 2. concurrency
if want concurrency; then
  section "Concurrency"
  N=32; [[ $QUICK -eq 1 ]] && N=8
  tool "$N parallel HTTP downloads"    parallel-download --count "$N" --path "/files/$SIZE.bin" --sha "$SHA"
  tool "$((N / 2)) parallel HTTPS downloads" parallel-download --tls --count $((N / 2)) --path "/files/$SIZE.bin" --sha "$SHA"
  tool "8 parallel HTTP uploads"       parallel-upload --count 8
  tool "8 parallel HTTPS uploads"      parallel-upload --tls --count 8
  echo "  -- same, under 1% loss + 20 ms delay"
  chaos_on "delay 20ms loss 1%"
  tool "[lossy] 8 parallel HTTP downloads" parallel-download --count 8 --path "/files/$SIZE.bin" --sha "$SHA"
  tool "[lossy] 4 parallel HTTPS uploads"  parallel-upload --tls --count 4 --size $((1 << 20))
  chaos_off
  alive_check
fi

# ------------------------------------------------------------------ 3. churn
if want churn; then
  section "Connection churn (session table and memory must not leak)"
  before=$(rss_mb)
  M=2000; [[ $QUICK -eq 1 ]] && M=500
  tool "$M sequential short HTTP connections"  many-short --count "$M"
  tool "$((M / 5)) sequential short HTTPS connections" many-short --tls --count $((M / 5))
  if command -v wrk >/dev/null; then
    rps=$(C wrk -t2 -c200 -d10s -H "Connection: close" "http://$SERVER_IP/api/health" 2>&1 | awk '/Requests\/sec/ {print $2}')
    errs=$(C wrk -t2 -c50 -d5s -H "Connection: close" "http://$SERVER_IP/" 2>&1 | grep -c "Socket errors" || true)
    info "wrk connect/close storm: ${rps:-?} req/s (new connection per request)"
    [[ "$errs" -eq 0 ]] && pass "no socket errors in a 5 s connect/close storm" || fail "socket errors during connect/close storm"
  fi
  sleep 35   # let idle sessions expire (Aethon ESTABLISHED timeout = 30 s)
  after=$(rss_mb)
  info "RSS before churn ${before} MB, after churn + expiry ${after} MB"
  awk -v b="$before" -v a="$after" 'BEGIN {exit !(a - b < 50)}' \
    && pass "memory returned to normal after churn (growth < 50 MB)" \
    || fail "memory grew by more than 50 MB after churn (possible session/buffer leak)"
  alive_check
fi

# ------------------------------------------------------------------ 4. protocol edges
if want edges; then
  section "Protocol edge cases"
  tool "half-close (client FIN right after request)" half-close
  tool "10 pipelined requests in one write (HTTP)"    pipeline --count 10
  tool "10 pipelined requests in one write (HTTPS)"   pipeline --tls --count 10
  tool "slow reader, 4 KB receive buffer (HTTP)"      slow-reader --path "/files/$SIZE.bin" --sha "$SHA"
  tool "slow reader, 4 KB receive buffer (HTTPS)"     slow-reader --tls --path "/files/$SIZE.bin" --sha "$SHA"
  tool "keep-alive connection idle for 40 s (HTTP)"   idle-keepalive --idle 40
  if [[ $LONG -eq 1 ]]; then
    big="$RUN_DIR/files/200mb.bin"
    [[ -f "$big" ]] || head -c $((200 << 20)) /dev/urandom > "$big"
    curl_sha   "200 MB HTTP download" "$(sha256sum "$big" | cut -d' ' -f1)" "http://$SERVER_IP/files/200mb.bin"
    curl_sha   "200 MB HTTPS download" "$(sha256sum "$big" | cut -d' ' -f1)" "${TLS[@]}" "https://test.local/files/200mb.bin"
    head -c $((100 << 20)) "$big" > "$RUN_DIR/up100.bin"
    upload_sha "100 MB HTTP upload"  "$RUN_DIR/up100.bin" "http://$SERVER_IP/api/upload"
    upload_sha "100 MB HTTPS upload" "$RUN_DIR/up100.bin" "https://test.local/api/upload" "${TLS[@]}"
  fi
  alive_check
fi

# ------------------------------------------------------------------ 5. attacks
if want attacks; then
  section "Adversarial clients"
  tool "DPI: '/etc/passwd' split across 3 segments"       split-evasion
  tool "DPI: '/etc/passwd' sent 1 byte per segment"       split-evasion --bytewise
  tool "DPI: '/etc/passwd' split across 3 TLS records"    split-evasion --tls
  tool "garbage on :80 and :443"                          garbage
  tool "20 downloads aborted with RST (HTTP)"             abort --count 20
  tool "20 uploads aborted with RST (HTTP)"               abort --mode upload --count 20
  tool "20 downloads aborted with RST (HTTPS)"            abort --tls --count 20
  tool "slowloris: 300 trickling connections for 15 s"   slowloris --conns 300 --seconds 15
  tool "TLS handshake flood (300, half abandoned)"       handshake-flood --count 300
  if [[ $LONG -eq 1 ]] && command -v hping3 >/dev/null; then
    echo "  -- 10 s spoofed SYN flood on :80 while a real client keeps requesting"
    C timeout 10 hping3 -S -p 80 --flood --rand-source -q "$SERVER_IP" >/dev/null 2>&1 &
    ok=0; total=0
    for _ in $(seq 1 8); do
      total=$((total + 1))
      C curl -sS --max-time 2 "http://$SERVER_IP/api/health" 2>/dev/null | grep -q '"ok":true' && ok=$((ok + 1))
      sleep 1
    done
    wait
    [[ $ok -eq $total ]] && pass "real client unaffected by SYN flood ($ok/$total)" \
      || fail "real client failed during SYN flood ($ok/$total ok); expected until SYN cookies exist"
    sleep 4   # half-open sessions expire after 3 s
  fi
  alive_check
fi

# ------------------------------------------------------------------ summary
echo
echo -e "\033[1mTorture result: $PASS passed, $FAIL failed, $INFO info\033[0m   (Aethon RSS now $(rss_mb) MB)"
[[ $FAIL -eq 0 ]]
