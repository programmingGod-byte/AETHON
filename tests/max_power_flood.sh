#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! ip netns list | grep -q "client_ns"; then
    echo "[-] Network namespace client_ns not found. Setting up virtual interfaces..."
    sudo ./veth0.bash
fi

PROTO="${1:-udp}"
PAYLOAD_SIZE="${2:-64}"
TARGET_IP="192.168.50.1"

PIDS=()
cleanup() {
    echo ""
    echo "[*] Stopping all flood workers..."
    for pid in "${PIDS[@]}"; do
        sudo kill -9 "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    echo "[+] All workers stopped cleanly."
    exit 0
}
trap cleanup SIGINT SIGTERM

echo "=========================================================="
echo "    AETHON MAX POWER FLOOD (4 MULTI-CORE HARDWARE QUEUES) "
echo "=========================================================="
echo "Target       : $TARGET_IP"
echo "Protocol     : $PROTO"
echo "Payload Size : $PAYLOAD_SIZE bytes"
echo "Client Cores : 4 (Cores 1, 2, 3, 4)"
echo "Target Queues: 4 (veth0 RX Queues 0-3)"
echo "Press Ctrl+C to stop the attack."
echo "=========================================================="

if [ "$PROTO" = "tcp" ]; then
    sudo ip netns exec client_ns taskset -c 1 hping3 -I veth1 --flood -S -p 80 -d "$PAYLOAD_SIZE" "$TARGET_IP" &
    PIDS+=($!)
    sudo ip netns exec client_ns taskset -c 2 hping3 -I veth1 --flood -S -p 80 -d "$PAYLOAD_SIZE" "$TARGET_IP" &
    PIDS+=($!)
    sudo ip netns exec client_ns taskset -c 3 hping3 -I veth1 --flood -S -p 80 -d "$PAYLOAD_SIZE" "$TARGET_IP" &
    PIDS+=($!)
    sudo ip netns exec client_ns taskset -c 4 hping3 -I veth1 --flood -S -p 80 -d "$PAYLOAD_SIZE" "$TARGET_IP" &
    PIDS+=($!)
else
    sudo ip netns exec client_ns taskset -c 1 hping3 -I veth1 --flood --udp -p 8080 -d "$PAYLOAD_SIZE" "$TARGET_IP" &
    PIDS+=($!)
    sudo ip netns exec client_ns taskset -c 2 hping3 -I veth1 --flood --udp -p 8081 -d "$PAYLOAD_SIZE" "$TARGET_IP" &
    PIDS+=($!)
    sudo ip netns exec client_ns taskset -c 3 hping3 -I veth1 --flood --udp -p 8082 -d "$PAYLOAD_SIZE" "$TARGET_IP" &
    PIDS+=($!)
    sudo ip netns exec client_ns taskset -c 4 hping3 -I veth1 --flood --udp -p 8083 -d "$PAYLOAD_SIZE" "$TARGET_IP" &
    PIDS+=($!)
fi

echo "[+] 4 Multi-Queue workers blasting simultaneously at maximum wire speed..."
wait

