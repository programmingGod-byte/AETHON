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
    echo "12) Python TLS SNI Domain Blocking & RST Injection Test"
    echo "13) Python TLS Encrypted Payload Decryption & DPI Exploit Test"
    echo "14) Full Functional TLS Test: Random Packets, Malicious Exploits & Flask Proxy"
    echo "15) Multi-Port Reverse Proxy Test: Ports 5000, 6000 & 8080 Routing"
    echo "16) Python TLS JA3 Fingerprint Rate Limiting Test"
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
        12)
            echo "🚀 Launching TLS SNI Domain Blocking & RST Injection Test..."
            sudo ip netns exec client_ns python3 tests/test_tls_sni.py 192.168.50.1 192.168.50.2 veth1
            ;;
        13)
            echo "🚀 Launching TLS Encrypted Payload Decryption & DPI Exploit Test..."
            sudo ip netns exec client_ns python3 tests/test_tls_payload.py 192.168.50.1 192.168.50.2 veth1 mydomain.com
            ;;
        14)
            echo "🚀 Launching Full Functional TLS Decryption, DPI & Flask Proxy Test..."
            BACKEND_STARTED=0
            if ! ss -tuln | grep -q ":8080 "; then
                echo "[*] Starting local backend server on port 8080..."
                python3 tests/flask_backend.py 8080 &
                BACKEND_PID=$!
                BACKEND_STARTED=1
                sleep 0.5
            fi
            sudo ip netns exec client_ns python3 tests/test_full_functional_tls.py 192.168.50.1 192.168.50.2 veth1 mydomain.com 8
            if [ "$BACKEND_STARTED" -eq 1 ]; then
                kill -9 $BACKEND_PID 2>/dev/null || true
            fi
            ;;
        15)
            echo "🚀 Launching Multi-Port (5000, 6000, 8080) Reverse Proxy & DPI Isolation Test..."
            fuser -k 5000/tcp 6000/tcp 8080/tcp 2>/dev/null || true
            sleep 0.2
            python3 tests/multi_backend_server.py &
            MULTI_PID=$!
            sleep 0.8
            sudo ip netns exec client_ns python3 tests/test_multi_port_forwarding.py 192.168.50.1 192.168.50.2 veth1
            kill -9 $MULTI_PID 2>/dev/null || true
            fuser -k 5000/tcp 6000/tcp 8080/tcp 2>/dev/null || true
            ;;
        16)
            echo "🚀 Launching TLS JA3 Fingerprint Rate Limiting Test..."
            sudo ip netns exec client_ns python3 tests/test_ja3_rate_limit.py 192.168.50.1 443 mydomain.com
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
    read -rp "Select test [1-16, q]: " CHOICE
    run_choice "$CHOICE"
fi

