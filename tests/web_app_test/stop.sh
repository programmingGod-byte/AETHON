#!/usr/bin/env bash
# Stops nginx and the Node backend started by start.sh.
#   --net   also remove veth0/client_ns and detach XDP from veth0
set -uo pipefail

RUN_DIR="${RUN_DIR:-/tmp/aethon_web_app_test}"

if [[ -f "$RUN_DIR/nginx.pid" ]]; then
  nginx -p "$RUN_DIR" -c "$RUN_DIR/nginx.conf" -s quit 2>/dev/null || kill "$(cat "$RUN_DIR/nginx.pid")" 2>/dev/null
  echo "[web_app_test] nginx stopped"
fi

if [[ -f "$RUN_DIR/node.pid" ]]; then
  kill "$(cat "$RUN_DIR/node.pid")" 2>/dev/null && echo "[web_app_test] node stopped"
  rm -f "$RUN_DIR/node.pid"
fi

if [[ "${1:-}" == "--net" ]]; then
  sudo ip netns exec client_ns tc qdisc del dev veth1 root 2>/dev/null || true
  sudo ip link set dev veth0 xdp off 2>/dev/null || true
  sudo ip link delete veth0 2>/dev/null || true
  sudo ip netns delete client_ns 2>/dev/null || true
  sudo rm -rf /sys/fs/bpf/aethon 2>/dev/null || true
  echo "[web_app_test] veth0/client_ns removed"
fi
