#!/usr/bin/env bash
# Starts the web app stack that Aethon protects on veth0:
#   client_ns (192.168.50.2) -> veth0 (192.168.50.1) -> Aethon -> nginx 127.0.0.1:8080 -> Node 127.0.0.1:3000
#
# Run as your normal user (not with sudo); it calls sudo only for network setup.
# Then start Aethon separately:  sudo ./build/src/afxdp_control veth0
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
RUN_DIR="${RUN_DIR:-/tmp/aethon_web_app_test}"
NODE_PORT=3000
NGINX_PORT=8080

info() { echo -e "\033[94m[web_app_test]\033[0m $*"; }
die()  { echo -e "\033[91m[web_app_test] $*\033[0m" >&2; exit 1; }

[[ $EUID -eq 0 ]] && die "Run as your normal user, not root (node via nvm is usually not on root's PATH)."
command -v node  >/dev/null || die "node not found (install Node.js >= 18)"
command -v nginx >/dev/null || die "nginx not found: sudo apt install -y nginx"
command -v curl  >/dev/null || die "curl not found"

# Refuse to start if something else already owns the ports
for port in $NODE_PORT $NGINX_PORT; do
  if ss -ltn "sport = :$port" | grep -q LISTEN; then
    die "port $port is already in use (run ./stop.sh, or stop the other service)"
  fi
done

# 1. Virtual network
if ! ip netns list | grep -qw client_ns; then
  info "creating veth0 <-> client_ns network"
  (cd "$ROOT" && ./veth0.bash)
fi
info "disabling offloads (TSO/GSO/GRO create frames larger than a 2 KB UMEM frame)"
sudo ethtool -K veth0 gro off gso off tso off tx off >/dev/null 2>&1 || true
sudo ip netns exec client_ns ethtool -K veth1 gro off gso off tso off tx off >/dev/null 2>&1 || true

# On veth the RX queue on veth0 = the client's TX queue. After a retransmission timeout Linux
# re-hashes the flow (net.core.txrehash), so it can jump to another TX queue -> another Aethon
# worker that has no session for it -> RST. A real NIC's RSS hashes the 4-tuple on the receiver,
# so a flow always stays on one queue; disable re-hashing in the client to behave the same.
info "disabling TX re-hashing in client_ns (keeps each flow on one queue, like NIC RSS)"
sudo ip netns exec client_ns sysctl -qw net.core.txrehash=0 || true

# 2. Runtime directories and large test files with known checksums
mkdir -p "$RUN_DIR"/{logs,files,tmp}
for mb in 1 5 50; do
  f="$RUN_DIR/files/${mb}mb.bin"
  if [[ ! -f "$f" ]]; then
    info "generating ${mb}mb.bin"
    head -c "$((mb * 1024 * 1024))" /dev/urandom > "$f"
  fi
done
(cd "$RUN_DIR/files" && sha256sum ./*.bin > SHA256SUMS)

# 3. nginx config
sed -e "s|__RUN_DIR__|$RUN_DIR|g" -e "s|__PUBLIC_DIR__|$DIR/public|g" \
  "$DIR/nginx/nginx.conf.template" > "$RUN_DIR/nginx.conf"

# 4. Node backend
info "starting Node backend on 127.0.0.1:$NODE_PORT"
HOST=127.0.0.1 PORT=$NODE_PORT DATA_DIR="$RUN_DIR/files" \
  nohup node "$DIR/backend/server.js" > "$RUN_DIR/logs/node.log" 2>&1 &
echo $! > "$RUN_DIR/node.pid"

# 5. nginx (-e sets the startup error log on nginx >= 1.19.5, avoiding /var/log/nginx)
info "starting nginx on 127.0.0.1:$NGINX_PORT"
NGINX_ARGS=(-p "$RUN_DIR" -c "$RUN_DIR/nginx.conf")
if nginx -h 2>&1 | grep -q -- '-e filename'; then
  NGINX_ARGS+=(-e "$RUN_DIR/logs/error.log")
fi
nginx "${NGINX_ARGS[@]}" -t >/dev/null 2>&1 || { nginx "${NGINX_ARGS[@]}" -t; die "nginx config test failed"; }
nginx "${NGINX_ARGS[@]}"

# 6. Health check (direct, from the host, without Aethon)
for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:$NGINX_PORT/api/health" >/dev/null 2>&1; then
    info "stack is up: http://127.0.0.1:$NGINX_PORT  (logs in $RUN_DIR/logs)"
    echo
    echo "Next:"
    echo "  1. Make sure rules/services.conf maps 192.168.50.1:80 (and :443 for TLS) to backend port $NGINX_PORT"
    echo "  2. Start Aethon from the repo root:   sudo ./build/src/afxdp_control veth0"
    echo "  3. Run the tests:                     $DIR/test.sh            (options: --netem, --load)"
    echo "  4. Stop everything:                   $DIR/stop.sh [--net]"
    exit 0
  fi
  sleep 0.25
done
die "stack did not become healthy; check $RUN_DIR/logs/{node.log,error.log}"
