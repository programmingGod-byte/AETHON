#!/bin/bash

# =========================================================
# AETHON VIRTUAL NETWORK SETUP SCRIPT (MULTI-QUEUE ENABLED)
# =========================================================

echo "🧹 1. Cleaning up any old network setups..."
# Ignore errors if they don't exist yet
sudo ip link delete veth0 2>/dev/null
sudo ip netns delete client_ns 2>/dev/null
sudo rm -rf /sys/fs/bpf/aethon 2>/dev/null || true


echo "🏗️ 2. Creating isolated Network Namespace (client_ns)..."
# This tricks Linux into thinking the client is a totally separate computer
sudo ip netns add client_ns


echo "🔌 3. Creating Virtual Ethernet (veth) cable with 4 QUEUES..."
# Creates a multi-queue virtual cable (4 RX / 4 TX queues for 4 CPU Cores)
sudo ip link add veth0 numrxqueues 4 numtxqueues 4 type veth peer name veth1 numrxqueues 4 numtxqueues 4


echo "🚪 4. Moving veth1 into the isolated client room..."
sudo ip link set veth1 netns client_ns


echo "🖥️ 5. Turning on Server (veth0) and assigning IP..."
sudo ip link set veth0 up
sudo ip addr add 192.168.50.1/24 dev veth0


echo "💻 6. Turning on Client (veth1) and assigning IP..."
# The 'lo' (loopback) interface must be up inside the namespace for networking to work
sudo ip netns exec client_ns ip link set lo up
sudo ip netns exec client_ns ip link set veth1 up
sudo ip netns exec client_ns ip addr add 192.168.50.2/24 dev veth1

echo "⚙️ 7. Disabling offloads and TX re-hashing..."
# TSO/GSO/GRO build frames larger than a 2 KB UMEM frame, and TX checksum offload leaves
# partial TCP checksums that Aethon (which verifies checksums) would reject.
sudo ethtool -K veth0 gro off gso off tso off tx off >/dev/null 2>&1
sudo ip netns exec client_ns ethtool -K veth1 gro off gso off tso off tx off >/dev/null 2>&1
# veth maps the client's TX queue to the RX queue; keep each flow on one queue like NIC RSS does
sudo ip netns exec client_ns sysctl -qw net.core.txrehash=0

echo "✅ Network is ready! veth0 (192.168.50.1) <---> veth1 (192.168.50.2) [4 Queues Active]"


# =========================================================
# DEBUGGING & TESTING COMMANDS CHEAT SHEET
# (Copy and paste these into your terminal when needed)
# =========================================================

# 🚀 1. RUN AETHON FIREWALL (From Aethon project root):
# sudo ./build/src/afxdp_control veth0

# 🔥 2. HIGH SPEED FLOOD (Tests 4 Multi-Queue Cores simultaneously):
# sudo ip netns exec client_ns hping3 -I veth1 --flood --rand-source -S -p 80 192.168.50.1

# 🛡️ 3. TEST TOKEN BUCKET RATE LIMITER (Drops traffic after 600 tokens):
# sudo ip netns exec client_ns hping3 -I veth1 --flood -S -p 80 192.168.50.1

# ⚡ 4. ICMP / UDP FLOOD TESTS:
# sudo ip netns exec client_ns ping -f 192.168.50.1
# sudo ip netns exec client_ns hping3 --flood --udp -p 8080 192.168.50.1

# 🔍 5. CHECK QUEUES & NETWORK INFO:
# ethtool -l veth0
# ip addr show veth0
# sudo ip netns exec client_ns ip addr show veth1

# 🧠 6. READ EBPF KERNEL LOGS (bpf_printk):
# sudo cat /sys/kernel/tracing/trace_pipe

# 🛑 7. STOP XDP & CLEANUP:
# sudo ip link set dev veth0 xdp off
# sudo ip link delete veth0
# sudo ip netns delete client_ns