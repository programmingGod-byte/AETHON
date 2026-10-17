#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! ip netns list | grep -q "client_ns"; then
    echo "[-] Network namespace client_ns not found. Setting up virtual interfaces..."
    sudo ./veth0.bash
fi

show_menu() {
    echo "=================================================="
    echo "              AETHON TEST SUITE                   "
    echo "=================================================="
    echo "1) hping3 UDP Flood (Wire-Speed, 64B payload)"
    echo "2) hping3 TCP SYN Flood (Multi-core Handshakes)"
    echo "3) hping3 ICMP Echo Flood"
    echo "4) Python 35,000 Active TCP Streams Benchmark"
    echo "5) Python TCP RST IPS Injection Test (MySQL exploit)"
    echo "6) Python DPI Hyperscan Signature Scanner Test"
    echo "7) Python TCP Fragmentation Evasion Attack Test"
    echo "8) 4-Core Parallel Hardware Saturation Flood (Max Power)"
    echo "9) C++20 Vectorized sendmmsg Blaster (Wire-Speed Mpps)"
    echo "10) Adversarial Chaos Torture Test (IMIX Sizes + Real Exploits)"
    echo "11) Stateful TCP Live Exploit & RST Torture Test (Triggers [ALERT] & [IPS BLOCK])"
    echo "q) Exit"
    echo "=================================================="
}

run_choice() {
    case "$1" in
        1)
            echo "🚀 Blasting UDP Flood on veth1 -> 192.168.50.1:8080 (Ctrl+C to stop)..."
            sudo ip netns exec client_ns hping3 -I veth1 --flood --udp -p 8080 -d 64 192.168.50.1
            ;;
        2)
            echo "🚀 Blasting TCP SYN Flood on veth1 -> 192.168.50.1:80 (Ctrl+C to stop)..."
            sudo ip netns exec client_ns hping3 -I veth1 --flood -S -p 80 -d 64 192.168.50.1
            ;;
        3)
            echo "🚀 Blasting ICMP Flood on veth1 -> 192.168.50.1 (Ctrl+C to stop)..."
            sudo ip netns exec client_ns hping3 -I veth1 --flood --icmp 192.168.50.1
            ;;
        4)
            echo "🚀 Streaming across 35,000 active TCP connections..."
            sudo ip netns exec client_ns python3 tests/traffic_generator.py 192.168.50.1 192.168.50.2 35000
            ;;
        5)
            echo "🚀 Injecting exploit and testing TCP RST generation..."
            sudo ip netns exec client_ns python3 tests/test_tcp_rst.py 192.168.50.1 192.168.50.2 veth1
            ;;
        6)
            echo "🚀 Testing DPI Hyperscan signatures with malicious payloads..."
            sudo ip netns exec client_ns python3 tests/test_dpi_scanner.py 192.168.50.1 192.168.50.2 80 8080
            ;;
        7)
            echo "🚀 Launching TCP fragmented evasion attack..."
            sudo ip netns exec client_ns python3 tests/tcp_frag_attack.py 192.168.50.1 veth1
            ;;
        8)
            echo "🚀 Launching 4-core parallel hardware saturation flood..."
            ./tests/max_power_flood.sh udp 64
            ;;
        9)
            echo "🚀 Launching C++20 vectorized sendmmsg blaster..."
            sudo ip netns exec client_ns ./build/src/max_power_blaster 192.168.50.1 udp 4 64
            ;;
        10)
            echo "🚀 Launching Adversarial Chaos Torture Test..."
            sudo ip netns exec client_ns ./build/src/chaos_torture_test 192.168.50.1 4
            ;;
        11)
            echo "🚀 Launching Stateful TCP Exploit & RST Torture Test..."
            sudo ip netns exec client_ns ./build/src/stateful_exploit_torture 192.168.50.1 4
            ;;
        q|Q)
            exit 0
            ;;
        *)
            echo "Invalid option: $1"
            exit 1
            ;;
    esac
}

if [ -n "$1" ]; then
    run_choice "$1"
else
    show_menu
    read -rp "Select test [1-7, q]: " CHOICE
    run_choice "$CHOICE"
fi

