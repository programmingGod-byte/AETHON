#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if ! ip netns list | grep -q "client_ns"; then
    echo "[-] Network namespace client_ns not found. Setting up virtual interfaces..."
    sudo ./veth0.bash
fi

echo "🚀 Running TCP RST Injection Test from client_ns..."
sudo ip netns exec client_ns python3 tests/test_tcp_rst.py 192.168.50.1 192.168.50.2 veth1

